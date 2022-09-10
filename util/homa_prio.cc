/* Copyright (c) 2020-2022 Stanford University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* This file contains a program that dynamically adjusts Homa's allocation
 * of priorities, based on recent traffic.  Type "homa_prio --help" for
 * information about command-line arguments.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "homa.h"

/* Values of command-line arguments (and their default values): */

FILE *log_file = stdout;
const char *log_file_name = NULL;
bool no_update = false;
int reconfig_interval = 1000;
double min_drift = 1.0;
int min_messages = 10000;
int unsched = 0;
double unsched_boost = 0.0;

enum Msg_Type {NORMAL, VERBOSE};

/** @log_level: only print log messages if they have a level <= this value. */
Msg_Type log_level = NORMAL;

extern void log(Msg_Type type, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * struct interval -  Keeps statistics for a range of message sizes
 *  (corresponds to a single line of the homa_metrics file).
 */
struct interval {
	/** @max_size: largest message size (in bytes) in this interval. */
	int max_size;

	/**
	 * @total_bytes: total number of bytes (over all time) in incoming
	 * messages in this size range.
	 */
	int64_t total_bytes;

	/**
	 * @total_messages: an estimate of the total number of messages
	 * in this interval (exact statistics are not kept).
	 */
	int64_t total_messages;

	/**
	 * @unsched_bytes: estimate of the total unscheduled bytes in
	 * incoming messages in this range (it's an estimate because we
	 * don't have the actual number of messages, so we have to estimate
	 * that).
	 */
	int64_t unsched_bytes;

	interval(int max_size, int64_t total_bytes, int64_t total_messages)
		: max_size(max_size)
		, total_bytes(total_bytes)
		, total_messages(total_messages)
	        , unsched_bytes(0)
	{}
};

/** struct metrics - Represents a single reading of Homa metrics. */
struct metrics {
	/**
	 * @intervals: bytes received for various intervals. Sorted in
	 * increasing order of message length.
	 */
	std::vector<interval> intervals;

	/* Homa metrics with the same name. */
	int64_t large_msg_count;
	int64_t large_msg_bytes;

	/** @total_bytes: total bytes received across all message sizes. */
	int64_t total_bytes;

	/**
	 * @estimated_msgs: total number of messages received (only an
	 * estimate; exact counts aren't kept).
	 */
	int64_t total_messages;
};

/**
 * log() - Print a message to the current log file
 * @type:   Kind of message (NORMAL or VERBOSE); used to control degree of
 *          log verbosity
 * @format: printf-style format string, followed by printf-style arguments.
 */
void log(Msg_Type type, const char *format, ...)
{
	char buffer[1000];
	struct timespec now;
	va_list args;

	if (type > log_level)
		return;
	if (strcmp(format, "\n") == 0) {
		fprintf(log_file, "\n");
		return;
	}
	va_start(args, format);
	clock_gettime(CLOCK_REALTIME, &now);

	vsnprintf(buffer, sizeof(buffer), format, args);
	fprintf(log_file, "%010lu.%09lu %s", now.tv_sec, now.tv_nsec, buffer);
}

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: homa_prio options\n\n"
		"Monitor incoming Homa traffic and adjust priorities for unscheduled\n"
		"packets to match recent traffic. The following options are available:\n"
		"--help            Print this message\n"
		"--interval        Time period over which traffic is averaged to compute\n"
		"                  priorities, in ms (default: %d)\n"
		"--log-file        Name of file in which to write log messages\n"
		"                  (default: stdin)\n"
		"--min-drift       Minimum amount by which the message size distribution\n"
		"                  must change before new cutoffs will be installed\n"
		"                  (default: %.1f). Intended to prevent churn; don't modify\n"
		"                  this unless you understand the code!\n"
		"--min-messages    Don't compute new cutoffs unless at least this many\n"
		"                  messages have been received since the last computation\n"
		"                  (default: %d)\n"
		"--no-update       Compute and print cutoffs, but don't modify Homa\n"
		"                  parameters\n"
		"--unsched         Always use this number of unscheduled priorities;\n"
		"                  0 means adjust based on workload (default: %d)\n"
		"--unsched_boost   Add this floating-point amount to the number of unscheduled\n"
		"                  priorities that would normally be used (default: 0.0)\n",
		reconfig_interval, min_drift, min_messages, unsched);
}

/**
 * get_param() - Read a Homa sysctl value.
 * @name:   Name of the desired parameter.
 * @value:  The value of the parameters stored here.
 *
 * Return:  True for success, false means the file couldn't be read or
 *          didn't contain an integer value (errors are logged after failures)
 */
bool get_param(const char *name, int *value)
{
	std::string path("/proc/sys/net/homa/");
	path.append(name);
	std::ifstream f(path);
	if (!f.is_open()) {
		log(NORMAL, "Couldn't open file %s: %s\n", path.c_str(),
			strerror(errno));
		return false;
	}
	std::string line;
	if (!getline(f, line)) {
		log(NORMAL, "No parameter value found in file %s.\n",
				path.c_str());
		f.close();
		return false;
	}
	f.close();

	char *end;
	*value = strtol(line.c_str(), &end, 10);
	if (end == line.c_str()) {
		log(NORMAL, "Expected integer in file %s, got '%s'\n",
			path.c_str(), line.c_str());
		return false;
	}
	return true;
}

/**
 * read_metrics() -  Read in a Homa metrics file and extract the traffic
 * statistics.
 * @path:      Path to file containing metrics; this file must be in
 *             the form output by Homa.
 * @metrics:   Will be filled in with all of the associated Homa statistics.
 *             If the statistics couldn't be read, then metrics->intervals
 *             will be empty.
 */
void read_metrics(const char *path, metrics *metrics)
{
	metrics->intervals.clear();
	metrics->large_msg_count = 0;
	metrics->large_msg_bytes = 0;
	metrics->total_bytes = 0;
	metrics->total_messages = 0;
	std::ifstream f(path);
	std::string line;
	if (!f.is_open()) {
		log(NORMAL, "Couldn't open metrics file %s: %s\n", path,
			strerror(errno));
		return;
	}
	while (getline(f, line)) {
		// Lines in the file start with a symbol name followed by
		// a count. Look for lines that start with "msg_bytes"
		// or "large_msg_bytes".
		size_t current_index = 0;
		uint64_t count;
		std::string symbol;
		const char *s;
		std::string value;
		char *end;

		size_t index = line.find(" ");
		if (index == std::string::npos)
			goto bad_line;
		symbol = line.substr(0, index);
		s = symbol.c_str();
		if ((strncmp(s, "msg_bytes_", 10) != 0)
				&& (strcmp(s, "large_msg_bytes") != 0)
				&& (strcmp(s, "large_msg_count") != 0))
			continue;

		// Extract the count.
		index = line.find_first_not_of(" ", index+1);
		if (index == std::string::npos)
			goto bad_line;
		value = line.substr(index, line.find(" ", index+1));
		count = strtoll(value.c_str(), &end, 10);
		if (end == value.c_str()) {
			log(NORMAL, "Bad count %s in line '%s'\n",
				value.c_str(), line.c_str());
			continue;
		}

		// Record data about the line.
		if (symbol[0] == 'm') {
			s += 10;
			int size = strtoul(s, &end, 10);
			if (end == s) {
				log(NORMAL, "Bad symbol %s; expected "
						"msg_bytes_ followed by"
						"number\n", symbol.c_str());
				continue;
			}

			/* See whether (a) there is an existing entry to
			 * increment, or (b) we need to add a new entry.
			 */
			if ((current_index > 0) && (size <= metrics
					->intervals[current_index].max_size))
				current_index = 0;
			while ((current_index < metrics->intervals.size()) &&
					(size > metrics->intervals[
					current_index].max_size))
				current_index++;
			if (current_index >= metrics->intervals.size()) {
				metrics->intervals.emplace_back(size, count, 0);
			} else if (metrics->intervals[current_index].max_size
					>= size) {
				interval *ivl = &metrics->intervals[current_index];
				ivl->total_bytes += count;
			} else {
				log(NORMAL, "Unexpected request size %d; "
						"inserting new entry with "
						"total_bytes %lu\n",
						size, count);
				metrics->intervals.emplace(
						metrics->intervals.begin()
						+ current_index,
						size, count, 0);
			}
			metrics->total_bytes += count;
			int prev_size = 0;
			if (current_index > 0)
				prev_size = metrics->intervals[current_index -1]
						.max_size;
			int messages = 2*count/(size + prev_size);
		        metrics->intervals[current_index].total_messages +=
				messages;
			metrics->total_messages += messages;
			continue;
		}
		if (strcmp(s, "large_msg_count") == 0) {
			metrics->total_messages += count;
			metrics->large_msg_count = count;
		} else {
			metrics->large_msg_bytes += count;
			metrics->total_bytes += count;
		}
		continue;

	    bad_line:
		log(NORMAL, "Couldn't parse line of metrics file: '%s'\n",
				line.c_str());
	}
	f.close();
}

/**
 * compute_cutoffs() -  Given information about recent traffic, compute
 * appropriate cutoffs for unscheduled priorities.
 * @diff:            Metrics containing traffic over a recent interval
 * @cutoffs:         Will be filled in with the message size cutoff for each
 *                   of the priority levels, suitable for storing in Homa's
 *                   unsched_cutoffs parameter.
 * @num_priorities:  Total number of priorities available for Homa (including
 *                   both scheduled and unscheduled).
 * @rtt_bytes:       Homa's rtt_bytes parameter (i.e., the maximum number of
 *                   unscheduled bytes in any message).
 */
void compute_cutoffs(metrics *diff, int cutoffs[8], int num_priorities,
		int rtt_bytes)
{
	int64_t total_bytes, total_unsched_bytes;
	int prev_size;

	// Compute the unscheduled bytes received over the interval.
	total_bytes = 0;
	total_unsched_bytes = 0;
	prev_size = 0;
	for (interval &interval: diff->intervals) {
		if (interval.max_size < prev_size)
			log(NORMAL, "Wrong interval order: size %d followed "
					"by %d\n",
					prev_size, interval.max_size);
		total_bytes += interval.total_bytes;
		if (interval.max_size <= rtt_bytes)
			interval.unsched_bytes = interval.total_bytes;
		else {
			interval.unsched_bytes = interval.total_messages
					* rtt_bytes;
			if (interval.unsched_bytes > interval.total_bytes)
				interval.unsched_bytes = interval.total_bytes;
		}
		total_unsched_bytes += interval.unsched_bytes;
		prev_size = interval.max_size;
	}
	total_bytes += diff->large_msg_bytes;
	total_unsched_bytes += diff->large_msg_count * rtt_bytes;

	// Divide priorities between scheduled and unscheduled packets.
	int64_t unsched_prios = unsched;
	if (unsched == 0) {
		double prios = static_cast<double>(num_priorities)
			* static_cast<double>(total_unsched_bytes)
		        / static_cast<double>(total_bytes);
		prios += unsched_boost + 0.5;
		unsched_prios = prios;
		if (unsched_prios < 1)
			unsched_prios = 1;
	}
	double total_mb = diff->total_bytes;
	total_mb *= 1e-6;
	double unsched_mb = total_unsched_bytes;
	unsched_mb *= 1e-6;
	double total_messages = diff->total_messages;
	total_messages *= 1e-3;
	log(NORMAL, "Statistics: %.1f K messages, %.1f MB total, "
			"%.1f MB unsched (%.1f%%), %ld unsched priorities\n",
			total_messages, total_mb, unsched_mb,
			100.0*unsched_mb/total_mb, unsched_prios);

	// Compute cutoffs for unscheduled priorities.
	int64_t bytes_per_prio;
	if (unsched_prios < num_priorities)
		bytes_per_prio = 1 + total_unsched_bytes/unsched_prios;
	else
		bytes_per_prio = 1 + total_bytes/num_priorities;
	int64_t next_cutoff_bytes = bytes_per_prio;
	int next_cutoff = num_priorities - 1;
	int cum_unsched_bytes = 0;
	for (interval &interval: diff->intervals) {
		cum_unsched_bytes += interval.unsched_bytes;
		if (cum_unsched_bytes >= total_unsched_bytes)
			break;
		if (cum_unsched_bytes >= next_cutoff_bytes) {
//			log(NORMAL, "Cutoff %d at length %d: %lu cumulative KB, "
//					"next_cutoff_bytes %lu KB\n",
//					next_cutoff, interval.max_size,
//					unsched_bytes/1000,
//					next_cutoff_bytes/1000);
			cutoffs[next_cutoff] = interval.max_size;
			next_cutoff--;
			next_cutoff_bytes = cum_unsched_bytes + bytes_per_prio;
			if (next_cutoff_bytes >= total_unsched_bytes)
				break;
		}

	}
	for ( ; next_cutoff >= 0; next_cutoff--)
		cutoffs[next_cutoff] = HOMA_MAX_MESSAGE_LENGTH;
	/* This isn't strictly needed, but it looks cleaner. */
	for (int i = num_priorities; i < 8; i++)
		cutoffs[i] = 0;
}

/**
 * install_cutoffs() - Update the cutoffs for unscheduled priorities
 * inside the Homa implementation on this machine.
 * @cutoffs:    Largest message size that may use each priority level
 *              (see documentation for Homa's unsched_cutoffs parameter
 *              for details).
 */
void install_cutoffs(int cutoffs[8])
{
	char buffer[200];
	snprintf(buffer, sizeof(buffer), "%d %d %d %d %d %d %d %d",
			cutoffs[0], cutoffs[1], cutoffs[2], cutoffs[3],
			cutoffs[4], cutoffs[5], cutoffs[6], cutoffs[7]);
	const char *path = "/proc/sys/net/homa/unsched_cutoffs";
	std::ofstream f(path, std::ofstream::out);
	if (!f.is_open()) {
		log(NORMAL, "Couldn't open %s to set priority cutoffs: %s\n",
			path, strerror(errno));
		return;
	}
	f << buffer;
	f.close();
}

/**
 * diff_metrics() - Compute the incremental traffic that occurred between
 * two cumulative metrics measurements.
 * @prev:    Cumulative metrics gathered earlier
 * @cur:     Cumulative metrics gathered more recently
 * @diff:    Will be modified to hold all the changes between @prev and @cur
 *
 * Return:   True means the difference was computed successfully; false means
 *           the metrics didn't have the same structure, so a difference
 *           it doesn't make sense.
 */
bool diff_metrics(metrics *prev, metrics *cur, metrics *diff)
{
	if (cur->intervals.size() != prev->intervals.size()) {
		log(NORMAL, "Metrics have different # intervals: "
				"current %lu, previous %lu\n",
				cur->intervals.size(), prev->intervals.size());
		return false;
	}
	diff->intervals.clear();
	for (size_t i = 0; i < cur->intervals.size(); i++) {
		interval &curi = cur->intervals[i];
		interval &previ = prev->intervals[i];
		if (curi.max_size != previ.max_size) {
			log(NORMAL, "Mismatch of interval max_sizes: "
					"%d vs. %d\n", curi.max_size,
					previ.max_size);
			return false;
		}
		diff->intervals.emplace_back(curi.max_size,
				curi.total_bytes - previ.total_bytes,
				curi.total_messages - previ.total_messages);
	}
	diff->large_msg_count = cur->large_msg_count - prev->large_msg_count;
	diff->large_msg_bytes = cur->large_msg_bytes - prev->large_msg_bytes;
	diff->total_bytes = cur->total_bytes - prev->total_bytes;
	diff->total_messages = cur->total_messages - prev->total_messages;
	return true;
}

/**
 * get_deciles() - Given set of metrics, compute a summary of the distribution
 * of message sizes.
 * @m:        Metrics describing a collection of messages.
 * @deciles:  This array will be filled in such that entry i (0 < i <= 8)
 *            holds the message length l such chat (i+1)*10% of all messages
 *            in m have a length <= l.
 */
void get_deciles(metrics *m, int deciles[9])
{
	int msgs_per_decile = m->total_messages/10;
	int64_t next_decile = msgs_per_decile;
	int64_t msgs_so_far = 0;
	int decile = 0;
	for (interval &interval: m->intervals) {
		msgs_so_far += interval.total_messages;
		if (interval.total_messages > 0)
		while (msgs_so_far >= next_decile) {
			deciles[decile] = interval.max_size;
			decile++;
			if (decile >= 9)
				goto loop_end;
			next_decile += msgs_per_decile;
		}
	}
    loop_end:
	for ( ; decile < 9; decile++)
		deciles[decile] = HOMA_MAX_MESSAGE_LENGTH;
}

/**
 * diff_deciles() - This function returns a measure of difference between
 * two sets of decile message distributions.
 * @d1:      A set of deciles returned by get_deciles.
 * @d2:      Another set of deciles returned by get_deciles.
 * Return:   The sum of the fractional differences between corresponding
 *           entries in the two decile arrays; each pair can contribute
 *           up to 1.0 to the result. A return value of 0 means that the
 *           two arrays were identical.
 */
double diff_deciles(int d1[9], int d2[9])
{
	double diff = 0.0;
	for (int i = 0; i < 9; i++) {
		double smaller, larger;
		if (d1[i] < d2[i]) {
			smaller = d1[i];
			larger = d2[i];
		} else {
			larger = d1[i];
			smaller = d2[i];
		}
		if (larger != 0)
			diff += (larger - smaller)/larger;
	}
	return diff;
}

/**
 * parse_doublet() - Parse an integer value from an argument word.
 * @argv:   Command-line arguments.
 * @i:      Index within argv of an option, which is supposed to be followed
 *          a floating-point value.
 * @value:  The floating-point value corresponding to @argv[i+1] is stored here,
 *          if the function completes successfully.
 * Return:  True means success, false means an error occurred (and a
 *          message was printed).
 */
bool parse_double(const char **argv, int i, double *value)
{
	double num;
	char *end;

	if (argv[i+1] == NULL) {
		printf("No value provided for %s\n", argv[i]);
		return false;
	}
	num = strtod(argv[i+1], &end);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be floating-point number\n",
				argv[i+1], argv[i]);
		return false;
	}
	*value = num;
	return true;
}

/**
 * parse_int() - Parse an integer value from an argument word.
 * @argv:   Command-line arguments.
 * @i:      Index within argv of an option, which is supposed to be followed
 *          an integer value.
 * @value:  The integer value corresponding to @argv[i+1] is stored here,
 *          if the function completes successfully.
 * Return:  True means success, false means an error occurred (and a
 *          message was printed).
 */
bool parse_int(const char **argv, int i, int *value)
{
	int num;
	char *end;

	if (argv[i+1] == NULL) {
		printf("No value provided for %s\n", argv[i]);
		return false;
	}
	num = strtol(argv[i+1], &end, 0);
	if (*end != 0) {
		printf("Bad value '%s' for %s; must be integer\n",
				argv[i+1], argv[i]);
		return false;
	}
	*value = num;
	return true;
}

int main(int argc, const char** argv)
{
	/* Parse arguments. */
	for (int i = 1; i < argc; i++) {
		const char *option = argv[i];

		if (strcmp(option, "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(option, "--interval") == 0) {
			if (!parse_int(argv, i, &reconfig_interval))
				exit(1);
			i++;
		} else if (strcmp(option, "--log-file") == 0) {
			log_file_name = argv[i+1];
			if (log_file_name == NULL){
				printf("No value provided for %s\n",
						option);
				exit(1);
			}
			log_file = fopen(log_file_name, "w");
			if (log_file == NULL) {
				printf("Couldn't open log file %s: %s\n",
					log_file_name, strerror(errno));
			}
			setlinebuf(log_file);
			i++;
		} else if (strcmp(option, "--min-drift") == 0) {
			if (!parse_double(argv, i, &min_drift))
				exit(1);
			i++;
		} else if (strcmp(option, "--min-messages") == 0) {
			if (!parse_int(argv, i, &min_messages))
				exit(1);
			i++;
		} else if (strcmp(option, "--no-update") == 0) {
			no_update = true;
		} else if (strcmp(option, "--unsched") == 0) {
			if (!parse_int(argv, i, &unsched))
				exit(1);
			i++;
		} else if (strcmp(option, "--unsched-boost") == 0) {
			if (!parse_double(argv, i, &unsched_boost))
				exit(1);
			i++;
		} else {
			printf("Unknown option '%s'\n", argv[i]);
			exit(1);
		}
	}

	metrics m[2];
	metrics *prev_metrics = &m[0];
	metrics *cur_metrics = &m[1];
	metrics diff;
	int prev_deciles[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	int cutoffs[8];
	int num_priorities = 1;
	int rtt_bytes = 0;
	int prev_num_priorities = -1;
	while (1) {
		usleep(1000*reconfig_interval);
		if (prev_metrics->intervals.empty()) {
			read_metrics("/proc/net/homa_metrics", prev_metrics);
			continue;
		}
		read_metrics("/proc/net/homa_metrics", cur_metrics);
		if (cur_metrics->intervals.empty())
			continue;
		if (!diff_metrics(prev_metrics, cur_metrics, &diff))
			continue;
		if (!get_param("num_priorities", &num_priorities)) {
			log(NORMAL, "get_param failed for num_priorities\n");
			continue;
		}
		if (!get_param("rtt_bytes", &rtt_bytes)) {
			log(NORMAL, "get_param failed for rtt_bytes\n");
			continue;
		}

		// Don't update the cutoffs until we've collected enough
		// data to provide reasonable statistics.
		if ((diff.total_messages < min_messages) ||
				(diff.total_bytes == 0))
			continue;
		metrics *tmp = prev_metrics;
		prev_metrics = cur_metrics;
		cur_metrics = tmp;

		if (num_priorities != prev_num_priorities) {
			log(NORMAL, "\n");
			log(NORMAL, "num_priorities changed from %d to %d\n",
					prev_num_priorities, num_priorities);
			if (num_priorities < 2)
				log(NORMAL, "Cutoff computation will stop "
					"until num_priorities > 1\n");
		}
		if (num_priorities == 1) {
			prev_num_priorities = num_priorities;
			continue;
		}

		int deciles[9];
		get_deciles(&diff, deciles);
		log(NORMAL, "\n");
		log(NORMAL, "Decile message distribution: %d %d %d %d %d "
				"%d %d %d %d\n",
				deciles[0], deciles[1], deciles[2], deciles[3],
				deciles[4], deciles[5], deciles[6], deciles[7],
				deciles[8]);
		double drift = diff_deciles(prev_deciles, deciles);
		if ((drift < min_drift)
				&& (num_priorities == prev_num_priorities)) {
			log(NORMAL, "Decile drift %.2f less than min-drift "
					"(%.2f); not updating\n",
					drift, min_drift);
			continue;
		}
		compute_cutoffs(&diff, cutoffs, num_priorities, rtt_bytes);
		log(NORMAL, "Decile drift %.2f, best cutoffs: %d %d %d %d "
				"%d %d %d %d\n",
				drift, cutoffs[0], cutoffs[1], cutoffs[2],
				cutoffs[3], cutoffs[4], cutoffs[5], cutoffs[6],
				cutoffs[7]);
		if (!no_update)
			install_cutoffs(cutoffs);
		for (int i = 0; i < 9; i++)
			prev_deciles[i] = deciles[i];
		prev_num_priorities = num_priorities;
	}
}