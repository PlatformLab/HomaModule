/* Copyright (c) 2020 Stanford University
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
int reconfig_interval = 1000;

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
	 * @unsched_bytes: estimate of the total unscheduled bytes in
	 * incoming messages in this range (it's an estimate because we
	 * don't have the actual number of messages, so we have to estimate
	 * that).
	 */
	int64_t unsched_bytes;
	
	interval(int max_size, int64_t total_bytes)
		: max_size(max_size)
		, total_bytes(total_bytes)
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
		"--log_file        Name of file in which to write log messages\n"
		"                  (default: stdin)\n",
		reconfig_interval);
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
				metrics->intervals.emplace_back(size, count);
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
						size, count);
			}
//			printf("Interval: %lu bytes, max_size %d\n", count, size);
			continue;
		}
		if (strcmp(s, "large_msg_count") == 0) {
			metrics->large_msg_count = count;
		} else {
			metrics->large_msg_bytes = count;
		}
		continue;
		
	    bad_line:
		log(NORMAL, "Couldn't parse line of metrics file: '%s'\n",
				line.c_str());
	}
	f.close();
}

/**
 * set_cutoffs() -  Given information about recent traffic, set Homa's
 * parameters for assigning packet priorities.
 * @diff:   Metrics containing traffic over a recent interval
 */
void set_cutoffs(metrics *diff)
{
	int num_priorities, rtt_bytes;
	int64_t total_bytes, total_unsched_bytes;
	int prev_size;
	int cutoffs[8];
	
	if (!get_param("num_priorities", &num_priorities)) {
		log(NORMAL, "get_param failed for num_priorities\n");
		return;
	}
	if (!get_param("rtt_bytes", &rtt_bytes)) {
		log(NORMAL, "get_param failed for rtt_bytes\n");
		return;
	}
	if (num_priorities == 1)
		return;
	
	// Count the total bytes and unscheduled bytes received over the
	// interval.
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
			int avg_size = (interval.max_size + prev_size)/2;
			interval.unsched_bytes = (interval.total_bytes/avg_size)
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
	int64_t unsched_prios = (total_unsched_bytes*num_priorities + total_bytes/2)
			/total_bytes;
	if (unsched_prios < 1)
		unsched_prios = 1;
	double total_mb = total_bytes;
	total_mb /= 1e06;
	double unsched_mb = total_unsched_bytes;
	unsched_mb /= 1e06;
	log(NORMAL, "Statistics: %.1f MB total, %.1f MB unsched (%.1f%%), "
			"%ld unsched priorities\n",
			total_mb, unsched_mb, 100.0*unsched_mb/total_mb,
			unsched_prios);
	
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
	
	char buffer[200];
	snprintf(buffer, sizeof(buffer), "%d %d %d %d %d %d %d %d",
			cutoffs[0], cutoffs[1], cutoffs[2], cutoffs[3],
			cutoffs[4], cutoffs[5], cutoffs[6], cutoffs[7]);
	log(NORMAL, "New cutoffs: %s\n", buffer);
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
				curi.total_bytes - previ.total_bytes);
	}
	diff->large_msg_count = cur->large_msg_count - prev->large_msg_count;
	diff->large_msg_bytes = cur->large_msg_bytes - prev->large_msg_bytes;
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
		} else if (strcmp(option, "--log_file") == 0) {
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
		} else {
			printf("Unknown option '%s'\n", argv[i]);
			exit(1);
		}
	}
	
	metrics m[2], diff;
	metrics *prev_metrics = &m[0];
	metrics *cur_metrics = &m[1];
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
		
		// Don't update the cutoffs until we've collected enough
		// data to provide reasonable statistics.
		uint64_t total_bytes = 0;
		for (interval &interval: diff.intervals)
			total_bytes += interval.total_bytes;
		total_bytes += diff.large_msg_bytes;
		if (total_bytes < 40000000)
			continue;
		
		set_cutoffs(&diff);
		metrics *tmp = prev_metrics;
		prev_metrics = cur_metrics;
		cur_metrics = tmp;
	}
}