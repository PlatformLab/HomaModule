/* Copyright (c) 2014-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include <mutex>

#include "time_trace.h"

__thread time_trace::buffer* time_trace::tb = NULL;
std::vector<time_trace::buffer*> time_trace::thread_buffers;
int time_trace::frozen = 0;

/**
 * @mutex: synchronizes accesses to thread_buffers.
 */
static std::mutex mutex;

/**
 * time_trace::free_unused() - Frees all of the thread-local buffers that
 * are no longer in use (they don't get freed when the thread_buffer
 * objects are deleted, in order to allow timetraces to be dumped after
 * threads have exited).
 */
void time_trace::cleanup()
{
	std::lock_guard<std::mutex> guard(mutex);
	for (int i = (int) (thread_buffers.size() - 1); i >= 0; i--) {
		time_trace::buffer *buffer = thread_buffers[i];
		if (buffer->ref_count == 0) {
			delete buffer;
			thread_buffers.erase(thread_buffers.begin() + i);
		}
	}
}

/**
 * freeze() - Stop all recording of trace events until they have been printed.
 */
void time_trace::freeze()
{
	frozen = 1;
}

/**
 * get_trace() - Return a string containing all of the trace records from all
 * of the thread-local buffers.
 */
std::string time_trace::get_trace()
{
	std::string s;
	time_trace::print_internal(&s, NULL);
	return s;
}

/**
 * print_internal() -  Does most of the work for both print_to_file and
 * get_trace.
 * @s:   If non-NULL, refers to a string that will hold a printout of the
 *       time trace.
 * @f:   If non-NULL, refers to an open file on which the trace will be
 *       printed.
 */
void
time_trace::print_internal(std::string *s, FILE *f)
{
	std::vector<time_trace::buffer*> buffers;

	freeze();

	/* Make a copy of thread_buffers in order to avoid potential
	 * synchronization issues with new threads modifying it.
	 */
	{
		std::lock_guard<std::mutex> guard(mutex);
		buffers = thread_buffers;
	}

	/* The index of the next event to consider from each buffer. */
	std::vector<int> current;

	/* Find the first (oldest) event in each trace. This will be events[0]
	 * if we never completely filled the buffer, otherwise events[next_index+1].
	 * This means we don't print the entry at next_index; this is convenient
	 * because it simplifies boundary conditions in the code below.
	 */
	for (uint32_t i = 0; i < buffers.size(); i++) {
		time_trace::buffer* buffer = buffers[i];
		int index = (buffer->next_index + 1) % buffer::BUFFER_SIZE;
		if (buffer->events[index].format != NULL) {
			current.push_back(index);
		} else {
			current.push_back(0);
		}
	}

	/* Decide on the time of the first event to be included in the output.
	 * This is most recent of the oldest times in all the traces (an empty
	 * trace has an "oldest time" of 0). The idea here is to make sure
	 * that there's no missing data in what we print (if trace A goes back
	 * farther than trace B, skip the older events in trace A, since there
	 * might have been related events that were once in trace B but have
	 * been overwritten).
	 */
	uint64_t start_time = 0;
	for (uint32_t i = 0; i < buffers.size(); i++) {
		event* event = &buffers[i]->events[current[i]];
		if ((event->format != NULL) && (event->timestamp > start_time)) {
			start_time = event->timestamp;
		}
	}

	// Skip all events before the starting time.
	for (uint32_t i = 0; i < buffers.size(); i++) {
		time_trace::buffer* buffer = buffers[i];
		while ((buffer->events[current[i]].format != NULL) &&
				(buffer->events[current[i]].timestamp
				< start_time) &&
				(current[i] != buffer->next_index)) {
		    current[i] = (current[i] + 1) % buffer::BUFFER_SIZE;
		}
	}

	// Output an initial (synthetic) record with the starting time.
	if (s != NULL) {
		char message[1000];
		snprintf(message, sizeof(message),
				"%9.3f us (+%8.3f us) [C0]   First event "
				"has timestamp %lu (cpu_ghz %.15f)",
				0.0, 0.0, start_time,
				get_cycles_per_sec()*1e-9);
		s->append(message);
	}
	if (f != NULL) {
		fprintf(f, "%9.3f us (+%8.3f us) [C0]   First event "
				"has timestamp %lu (cpu_ghz %.15f)\n",
				0.0, 0.0, start_time,
				get_cycles_per_sec()*1e-9);
	}

	/* Each iteration through this loop processes one event (the one with
	 * the earliest timestamp).
	 */
	double prev_micros = 0.0;
	while (1) {
		time_trace::buffer* buffer;
		event* event;

		/* Check all the traces to find the earliest available event. */
		uint32_t cur_buf = ~0;
		uint64_t earliest_time = ~0;
		for (uint32_t i = 0; i < buffers.size(); i++) {
			buffer = buffers[i];
			event = &buffer->events[current[i]];
			if ((current[i] != buffer->next_index)
					&& (event->format != NULL)
					&& (event->timestamp < earliest_time)) {
				cur_buf = i;
				earliest_time = event->timestamp;
			}
		}
		if (cur_buf == ~0U)
			break;
		buffer = buffers[cur_buf];
		event = &buffer->events[current[cur_buf]];
		current[cur_buf] = (current[cur_buf] + 1) % buffer::BUFFER_SIZE;

		char message[1000];
		char core_id[20];
		snprintf(core_id, sizeof(core_id), "[%s]",
				buffer->name.c_str());
		double micros = to_seconds(event->timestamp - start_time) *1e6;
		if (s != NULL) {
			snprintf(message, sizeof(message),
					"\n%9.3f us (+%8.3f us) %-6s ",
					micros, micros - prev_micros, core_id);
			s->append(message);
			snprintf(message, sizeof(message), event->format,
					event->arg0, event->arg1, event->arg2,
					event->arg3);
			s->append(message);
		}
		if (f != NULL) {
			fprintf(f, "%9.3f us (+%8.3f us) %-6s ", micros,
					micros - prev_micros, core_id);
			fprintf(f, event->format, event->arg0, event->arg1,
					event->arg2, event->arg3);
			fprintf(f, "\n");
		}
		prev_micros = micros;
	}
	frozen = 0;
}

/**
 * print_to_file() - Print all of the accumulated time trace entries to
 * a given file.
 * @name:   Name of the file in which to print the entries.
 * Return:  Zero means success. Nonzero means that the given name couldn't
 *          be opened, and the return value is the errno describing the
 *          problem.
 */
int
time_trace::print_to_file(const char *name)
{
	FILE *f = fopen(name, "w");
	if (f == NULL)
		return errno;
	print_internal(NULL, f);
	fclose(f);
	return 0;
}

/**
 * time_trace::buffer::buffer() - Construct a time_trace::buffer.
 * @name:  Short name for this buffer; will be included in trace printouts.
 */
time_trace::buffer::buffer(std::string name)
	: name(name)
	, next_index(0)
        , ref_count(0)
	, events()
{
	// Mark all of the events invalid.
	for (uint32_t i = 0; i < BUFFER_SIZE; i++) {
		events[i].format = NULL;
	}
}

/**
 * time_trace::buffer::~buffer() - Destructor for time_trace::buffers.
 */
time_trace::buffer::~buffer()
{
}

/**
 * time_trace::buffer::record() - Record an event in the buffer.
 * @timestamp: The time at which the event occurred.
 * @format:    A format string for snprintf that will be used, along
 *             with arg0..arg3, to generate a human-readable message
 *             describing what happened, when the time trace is printed.
 *             The message is generated by calling snprintf as follows:
 *             snprintf(buffer, size, format, arg0, arg1, arg2, arg3)
 *             where format and arg0..arg3 are the corresponding
 *             arguments to this method. This pointer is stored in the
 *             time trace, so the caller must ensure that its contents
 *             will not change over its lifetime in the trace.
 * @arg0:      Argument to use when printing a message about this event.
 * @arg1:      Argument to use when printing a message about this event.
 * @arg2:      Argument to use when printing a message about this event.
 * @arg3:      Argument to use when printing a message about this event.
 */
void time_trace::buffer::record(uint64_t timestamp, const char* format,
        uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
	event* event = &events[next_index];
	if (frozen)
		return;
	next_index = (next_index + 1) & BUFFER_MASK;

	event->timestamp = timestamp;
	event->format = format;
	event->arg0 = arg0;
	event->arg1 = arg1;
	event->arg2 = arg2;
	event->arg3 = arg3;
}

/**
 * time_trace::thread_buffer::thread_buffer() - Constructor for thread_buffers.
 * Creates a thread-private time_trace::buffer object for the current thread,
 * if one doesn't already exist.
 * @name:  Short descriptive name for the current thread; will appear in
 *         time trace printouts.
 */
time_trace::thread_buffer::thread_buffer(std::string name)
	: buffer(NULL)
{
	std::lock_guard<std::mutex> guard(mutex);
	if (tb == NULL) {
		tb = new time_trace::buffer(name);
		thread_buffers.push_back(tb);
		tt("Created new thread_buffer");
	}
	buffer = tb;
	buffer->ref_count++;
}

/**
 * time_trace::thread_buffer::thread_buffer() - Destructor for
 * thread_buffers. Deletes the thread-private variable if there are no more
 * objects referring to the buffer.
 */
time_trace::thread_buffer::~thread_buffer()
{
	std::lock_guard<std::mutex> guard(mutex);
	buffer->ref_count--;
	if (buffer->ref_count == 0)
		tb = NULL;
}