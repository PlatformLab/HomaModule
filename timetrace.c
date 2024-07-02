/* Copyright (c) 2019-2023 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

#include "homa_impl.h"

#ifndef __UNIT_TEST__
/* Uncomment the line below if the main Linux kernel has been compiled with
 * timetrace stubs; we will then connect the timetrace mechanism here with
 * those stubs to allow the rest of the kernel to log in our buffers.
 */
//#define TT_KERNEL 1
#endif
#ifdef TT_KERNEL
extern int        tt_linux_buffer_mask;
extern struct tt_buffer *tt_linux_buffers[];
extern void       (*tt_linux_freeze)(void);
extern atomic_t  *tt_linux_freeze_count;
extern atomic_t   tt_linux_freeze_no_homa;
extern int       *tt_linux_homa_temp;
extern int        tt_linux_homa_temp_default[];
extern void       tt_inc_metric(int metric, __u64 count);
extern void       (*tt_linux_inc_metrics)(int metric, __u64 count);
extern void       tt_linux_skip_metrics(int metric, __u64 count);
extern void       (*tt_linux_printk)(void);
extern void       (*tt_linux_dbg1)(char *msg, ...);
extern void       (*tt_linux_dbg2)(char *msg, ...);
extern void       (*tt_linux_dbg3)(char *msg, ...);
extern void       tt_linux_nop(void);
extern void       homa_trace(__u64 u0, __u64 u1, int i0, int i1);
#endif

/* Separate buffers for each core: this eliminates the need for
 * synchronization in tt_record, which improves performance significantly.
 * NR_CPUS is an overestimate of the actual number of cores; we use it
 * here, rather than nr_cpu_ids, because it allows for static allocation
 * of this array. And
 */
struct tt_buffer *tt_buffers[NR_CPUS];

/* Describes file operations implemented for reading timetraces
 * from /proc.
 */
static const struct proc_ops tt_pops = {
	.proc_open              = tt_proc_open,
	.proc_read              = tt_proc_read,
	.proc_lseek             = tt_proc_lseek,
	.proc_release           = tt_proc_release
};

/* Used to remove the /proc file during tt_destroy. */
static struct proc_dir_entry *tt_dir_entry;

/* Synchronizes accesses to global state such as frozen and init.  A mutex
 * isn't safe here, because tt_freeze gets called at times when threads
 * can't sleep.
 */
static spinlock_t tt_lock;

/* No new timetrace entries will be made whenever this is nonzero (counts
 * the number of active /proc reads, plus 1 more if tt_frozen is true).
 * Always nonzero when we're not initialized.
 */
atomic_t tt_freeze_count = {.counter = 1};

/* True means that tt_freeze has been called since the last time the
 * timetrace was read.
 */
bool tt_frozen;

/* True means timetrace has been successfully initialized. */
static bool init;

/* Used instead of TT_BUF_SIZE in places that are not performance
 * critical, so tests can override to simplify testing. Must be a
 * power of 2.
 */
int tt_buffer_size = TT_BUF_SIZE;

/* Used instead of PF_BUF_SIZE, so tests can override to simplify testing. */
int tt_pf_storage = TT_PF_BUF_SIZE;

/* Set during tests to disable "cpu_khz" line in trace output. */
bool tt_test_no_khz = false;

/**
 * tt_init(): Enable time tracing, create /proc file for reading traces.
 * @proc_file: Name of a file in /proc; this file can be read to extract
 *             the current timetrace. NULL means don't create a /proc file
 *             (such as when running unit tests).
 * @temp:      Pointer to homa's "temp" configuration parameters, which
 *             we should make available to the kernel. NULL means no
 *             such variables available.
 *
 * Return :    0 means success, anything else means an error occurred (a
 *             log message will be printed to describe the error).
 */
int tt_init(char *proc_file, int *temp)
{
	int i;

	if (init) {
		return 0;
	}

	for (i = 0; i < nr_cpu_ids; i++) {
		struct tt_buffer *buffer;
		buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
		if (buffer == NULL) {
			printk(KERN_ERR "timetrace couldn't allocate "
					"tt_buffers\n");
			goto error;
		}
		memset(buffer, 0, sizeof(*buffer));
		tt_buffers[i] = buffer;
	}

	if (proc_file != NULL) {
		tt_dir_entry = proc_create(proc_file, S_IRUGO, NULL, &tt_pops);
		if (!tt_dir_entry) {
			printk(KERN_ERR "couldn't create /proc/%s for timetrace "
					"reading\n", proc_file);
			goto error;
		}
	} else {
		tt_dir_entry = NULL;
	}

	spin_lock_init(&tt_lock);
	tt_freeze_count.counter = 0;
	tt_frozen = false;
	init = true;

#ifdef TT_KERNEL
	for (i = 0; i < nr_cpu_ids; i++) {
		tt_linux_buffers[i] = tt_buffers[i];
	}
	tt_linux_buffer_mask = TT_BUF_SIZE-1;
	tt_linux_freeze = tt_freeze;
	tt_linux_freeze_count = &tt_freeze_count;
	tt_linux_inc_metrics = tt_inc_metric;
	tt_linux_printk = tt_printk;
	tt_linux_dbg1 = tt_dbg1;
	tt_linux_dbg2 = tt_dbg2;
	tt_linux_dbg3 = tt_dbg3;
	if (temp)
		tt_linux_homa_temp = temp;
#endif

	return 0;

	error:
	for (i = 0; i < nr_cpu_ids; i++) {
		kfree(tt_buffers[i]);
		tt_buffers[i] = NULL;
	}
	return -1;
}

/**
 * @tt_destroy(): Disable time tracing and disable the /proc file for
 * reading traces.
 */
void tt_destroy(void)
{
	int i;
	spin_lock(&tt_lock);
	if (init) {
		init = false;
		if (tt_dir_entry != NULL)
			proc_remove(tt_dir_entry);
	}
	for (i = 0; i < nr_cpu_ids; i++) {
		kfree(tt_buffers[i]);
		tt_buffers[i] = NULL;
	}
	tt_freeze_count.counter = 1;

#ifdef TT_KERNEL
	tt_linux_freeze = tt_linux_nop;
	tt_linux_freeze_count = &tt_linux_freeze_no_homa;
	for (i = 0; i < nr_cpu_ids; i++) {
		tt_linux_buffers[i] = NULL;
	}
	tt_linux_inc_metrics = tt_linux_skip_metrics;
	tt_linux_printk = tt_linux_nop;
	tt_linux_dbg1 = (void (*)(char *, ...)) tt_linux_nop;
	tt_linux_dbg2 = (void (*)(char *, ...)) tt_linux_nop;
	tt_linux_dbg3 = (void (*)(char *, ...)) tt_linux_nop;
	for (i = 0; i < 100; i++) {
		tt_debug_int64[i] = 0;
		tt_debug_ptr[i] = 0;
	}
	tt_linux_homa_temp = tt_linux_homa_temp_default;
#endif

	spin_unlock(&tt_lock);
}

/**
 * Stop recording timetrace events until the trace has been read
 * using the /proc file. When recording resumes after reading the
 * file, the buffers will be cleared.
 */
void tt_freeze(void)
{
	if (tt_frozen)
		return;
	tt_record("timetrace frozen");
	printk(KERN_NOTICE "tt_freeze invoked\n");
	spin_lock(&tt_lock);
	if (!tt_frozen) {
		tt_frozen = true;
		atomic_inc(&tt_freeze_count);
	}
	spin_unlock(&tt_lock);
}

/**
 * tt_record_buf(): record an event in a core-specific tt_buffer.
 *
 * @buffer:    Buffer in which to record the event.
 * @timestamp: The time at which the event occurred (rdtsc units)
 * @format:    Format string for snprintf that will be used, along with
 *             arg0..arg3, to generate a human-readable message describing
 *             what happened, when the time trace is printed. The message
 *             is generated by calling snprintf as follows:
 *                 snprintf(buffer, size, format, arg0, arg1, arg2, arg3)
 *             where format and arg0..arg3 are the corresponding arguments
 *             to this method. This pointer is stored in the buffer, so
 *             the caller must ensure that its contents will not change
 *             over its lifetime in the trace.
 * @arg0       Argument to use when printing a message about this event.
 * @arg1       Argument to use when printing a message about this event.
 * @arg2       Argument to use when printing a message about this event.
 * @arg3       Argument to use when printing a message about this event.
 */
void tt_record_buf(struct tt_buffer *buffer, __u64 timestamp,
		const char* format, __u32 arg0, __u32 arg1, __u32 arg2,
		__u32 arg3)
{
	struct tt_event *event;
	if (unlikely(atomic_read(&tt_freeze_count) > 0)) {
		// In order to ensure that reads produce consistent
		// results, don't record concurrently (this could cause
		// some events to be dropped).
		return;
	}

	event = &buffer->events[buffer->next_index];
	buffer->next_index = (buffer->next_index + 1)
#ifdef __UNIT_TEST__
		& (tt_buffer_size-1);
#else
		& (TT_BUF_SIZE-1);
#endif

	event->timestamp = timestamp;
	event->format = format;
	event->arg0 = arg0;
	event->arg1 = arg1;
	event->arg2 = arg2;
	event->arg3 = arg3;
}

/**
 * tt_find_oldest() - This function is invoked when printing out the
 * Timetrace: it finds the oldest event to print from each trace.
 * This will be events[0] if we never completely filled the buffer,
 * otherwise events[nextIndex+1]. This means we don't print the entry at
 * nextIndex; this is convenient because it simplifies boundary checks
 * later on while printing records. In addition, if any buffer has
 * wrapped around, then events with times less than the oldest in that
 * buffer will be skipped (data from earlier than this is not necessarily
 * complete, since there may have been events that were discarded).
 * @pos:   Array with NPOS elements; will be filled in with the oldest
 *         index in the trace for each core.
 */
void tt_find_oldest(int *pos)
{
	struct tt_buffer* buffer;
	int i;
	__u64 start_time = 0;

	for (i = 0; i < nr_cpu_ids; i++) {
		buffer = tt_buffers[i];
		if (buffer->events[tt_buffer_size-1].format == NULL) {
			pos[i] = 0;
		} else {
			int index = (buffer->next_index + 1)
					& (tt_buffer_size-1);
			struct tt_event *event = &buffer->events[index];
			pos[i] = index;
			if (event->timestamp > start_time) {
				start_time = event->timestamp;
			}
		}
	}

	/* Skip over all events before start_time, in order to make
	 * sure that there's no missing data in what we print.
	 */
	for (i = 0; i < nr_cpu_ids; i++) {
		buffer = tt_buffers[i];
		while ((buffer->events[pos[i]].timestamp < start_time)
				&& (pos[i] != buffer->next_index)) {
			pos[i] = (pos[i] + 1) & (tt_buffer_size-1);
		}
	}
}

/**
 * tt_proc_open() - This function is invoked when /proc/timetrace is
 * opened to read timetrace info.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 *
 * Return:    0 for success, else a negative errno.
 */
int tt_proc_open(struct inode *inode, struct file *file)
{
	struct tt_proc_file* pf = NULL;
	int result = 0;

	spin_lock(&tt_lock);
	if (!init) {
		result = -EINVAL;
		goto done;
	}
	pf = kmalloc(sizeof(*pf), GFP_KERNEL);
	if (pf == NULL) {
		result = -ENOMEM;
		goto done;
	}
	pf->file = file;
	pf->bytes_available = 0;
	pf->next_byte = pf->msg_storage;

	atomic_inc(&tt_freeze_count);
	tt_find_oldest(pf->pos);
	file->private_data = pf;

	if (!tt_test_no_khz) {
		pf->bytes_available = snprintf(pf->msg_storage, TT_PF_BUF_SIZE,
				"cpu_khz: %u\n", cpu_khz);
	}

	done:
	spin_unlock(&tt_lock);
	return result;
}

/**
 * tt_proc_read() - This function is invoked to handle read kernel calls on
 * /proc/timetrace.
 * @file:    Information about the file being read.
 * @buffer:  Address in user space of the buffer in which data from the file
 *           should be returned.
 * @length:  Number of bytes available at @buffer.
 * @offset:  Current read offset within the file. For now, we assume I/O
 *           is done sequentially, so we ignore this.
 *
 * Return: the number of bytes returned at @buffer. 0 means the end of the
 * file was reached, and a negative number indicates an error (-errno).
 */
ssize_t tt_proc_read(struct file *file, char __user *user_buf,
		size_t length, loff_t *offset)
{
	/* # bytes of data that have accumulated in pf->msg_storage but
	 * haven't been copied to user space yet.
	 */
	int copied_to_user = 0;
	struct tt_proc_file *pf = file->private_data;

	spin_lock(&tt_lock);
	if ((pf == NULL) || (pf->file != file)) {
		printk(KERN_ERR "tt_metrics_read found damaged "
				"private_data: 0x%p\n", file->private_data);
		copied_to_user = -EINVAL;
		goto done;
	}

	if (!init)
		goto done;

	/* Each iteration through this loop processes one event (the one
	 * with the earliest timestamp). We buffer data until pf->msg_storage
	 * is full, then copy to user space and repeat.
	 */
	while (true) {
		struct tt_event *event;
		int entry_length, chunk_size, available, i, failed_to_copy;
		int current_core = -1;
		__u64 earliest_time = ~0;

		/* Check all the traces to find the earliest available event. */
		for (i = 0; i < nr_cpu_ids; i++) {
			struct tt_buffer *buffer = tt_buffers[i];
			event = &buffer->events[pf->pos[i]];
			if ((pf->pos[i] != buffer->next_index)
					&& (event->timestamp < earliest_time)) {
			    current_core = i;
			    earliest_time = event->timestamp;
			}
		}
		if (current_core < 0) {
		    /* None of the traces have any more events to process. */
		    goto flush;
		}

		/* Format one event. */
		event = &(tt_buffers[current_core]->events[
				pf->pos[current_core]]);
		available = tt_pf_storage - (pf->next_byte + pf->bytes_available
				- pf->msg_storage);
		if (available == 0) {
			goto flush;
		}
		entry_length = snprintf(pf->next_byte + pf->bytes_available,
				available, "%lu [C%02d] ",
				(long unsigned int) event->timestamp,
			        current_core);
		if (available >= entry_length)
			entry_length += snprintf(pf->next_byte
					+ pf->bytes_available + entry_length,
					available - entry_length,
					event->format, event->arg0,
					event->arg1, event->arg2, event->arg3);
		if (entry_length >= available) {
			/* Not enough room for this entry. */
			if (pf->bytes_available == 0) {
				/* Even a full buffer isn't enough for
				 * this entry; truncate the entry. */
				entry_length = available - 1;
			} else {
				goto flush;
			}
		}
		/* Replace terminating null character with newline. */
		pf->next_byte[pf->bytes_available + entry_length] = '\n';
		pf->bytes_available += entry_length + 1;
		pf->pos[current_core] = (pf->pos[current_core] + 1)
				& (tt_buffer_size-1);
		continue;

		flush:
		chunk_size = pf->bytes_available;
		if (chunk_size > (length - copied_to_user)) {
			chunk_size = length - copied_to_user;
		}
		if (chunk_size == 0)
			goto done;
		failed_to_copy = copy_to_user(user_buf + copied_to_user,
				pf->next_byte, chunk_size);
		chunk_size -= failed_to_copy;
		pf->bytes_available -= chunk_size;
		if (pf->bytes_available == 0)
			pf->next_byte = pf->msg_storage;
		else
			pf->next_byte += chunk_size;
		copied_to_user += chunk_size;
		if (failed_to_copy != 0) {
			if (copied_to_user == 0)
				copied_to_user = -EFAULT;
			goto done;
		}
	}

	done:
	spin_unlock(&tt_lock);
	return copied_to_user;
}


/**
 * tt_proc_lseek() - This function is invoked to handle seeks on
 * /proc/timetrace. Right now seeks are ignored: the file must be
 * read sequentially.
 * @file:    Information about the file being read.
 * @offset:  Distance to seek, in bytes
 * @whence:  Starting point from which to measure the distance to seek.
 */
loff_t tt_proc_lseek(struct file *file, loff_t offset, int whence)
{
	return 0;
}

/**
 * tt_proc_release() - This function is invoked when the last reference to
 * an open /proc/timetrace is closed.  It performs cleanup.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 *
 * Return: 0 for success, or a negative errno if there was an error.
 */
int tt_proc_release(struct inode *inode, struct file *file)
{
	int i;

	struct tt_proc_file *pf = file->private_data;
	if ((pf == NULL) || (pf->file != file)) {
		printk(KERN_ERR "tt_metrics_release found damaged "
				"private_data: 0x%p\n", file->private_data);
		return -EINVAL;
	}

	kfree(pf);
	file->private_data = NULL;

	spin_lock(&tt_lock);

	if (init) {
		if (tt_frozen && (atomic_read(&tt_freeze_count) == 2)) {
			atomic_dec(&tt_freeze_count);
			tt_frozen = false;
		}

		if (atomic_read(&tt_freeze_count) == 1) {
			/* We are the last active open of the file; reset all of
			 * the buffers to "empty".
			 */
			for (i = 0; i < nr_cpu_ids; i++) {
				struct tt_buffer *buffer = tt_buffers[i];
				buffer->events[tt_buffer_size-1].format = NULL;
				buffer->next_index = 0;
			}
		}
		atomic_dec(&tt_freeze_count);
	}

	spin_unlock(&tt_lock);
	return 0;
}

/**
 * tt_print_file() - Print the contents of the timetrace to a given file.
 * Useful in situations where the system is too unstable to extract a
 * timetrace by reading /proc/timetrace. Unfortunately, this function cannot
 * be invoked when preemption was disabled (e.g., when holding a spin lock).
 * As of 2/2024, this function is not reliable in situations where the machine
 * is about to crash.  It seems to print the trace, but after reboot the
 * file isn't there.
 * @file:  Name of the file in which to print the timetrace; should be
 *         an absolute file name.
 */
void tt_print_file(char *path)
{
	/* Index of the next entry to return from each tt_buffer.
	 * This array is too large to allocate on the stack, and we don't
	 * want to allocate space dynamically (this function could be
	 * called at a point where the world is going to hell). So,
	 * allocate the array statically, and only allow one concurrent
	 * call to this function.
	 */
	static int pos[NR_CPUS];
	static atomic_t active;
	struct file *filp = NULL;
	int err;

	/* Also use a static buffer for accumulating output data. */
	static char buffer[10000];
	int bytes_used = 0;
	loff_t offset = 0;

	printk(KERN_ERR "tt_print_file starting, file %s\n", path);

	if (atomic_xchg(&active, 1)) {
		printk(KERN_ERR "concurrent call to tt_print_file aborting\n");
		return;
	}
	if (!init)
		return;

	filp = filp_open(path, O_WRONLY | O_CREAT, 0666);
	if (IS_ERR(filp)) {
		printk(KERN_ERR "tt_print_file couldn't open %s: "
				"error %ld\n", path, -PTR_ERR(filp));
		filp = NULL;
		goto done;
	}

	tt_record("tt_print_file printing timetrace");
	atomic_inc(&tt_freeze_count);
	tt_find_oldest(pos);

	bytes_used += snprintf(buffer + bytes_used,
			sizeof(buffer) - bytes_used,
			"cpu_khz: %u\n", cpu_khz);

	/* Each iteration of this loop printk's one event. */
	while (true) {
		struct tt_event *event;
		int i;
		int current_core = -1;
		__u64 earliest_time = ~0;

		/* Check all the traces to find the earliest available event. */
		for (i = 0; i < nr_cpu_ids; i++) {
			struct tt_buffer *buffer = tt_buffers[i];
			event = &buffer->events[pos[i]];
			if ((pos[i] != buffer->next_index)
					&& (event->timestamp < earliest_time)) {
			    current_core = i;
			    earliest_time = event->timestamp;
			}
		}
		if (current_core < 0) {
		    /* None of the traces have any more events to process. */
		    break;
		}
		event = &(tt_buffers[current_core]->events[
				pos[current_core]]);
		pos[current_core] = (pos[current_core] + 1)
				& (tt_buffer_size-1);

		bytes_used += snprintf(buffer + bytes_used,
				sizeof(buffer) - bytes_used,
				"%lu [C%02d] ",
				(long unsigned int) event->timestamp,
				current_core);
		bytes_used += snprintf(buffer + bytes_used,
				sizeof(buffer) - bytes_used,
				event->format, event->arg0,
				event->arg1, event->arg2, event->arg3);
		if (bytes_used < sizeof(buffer)) {
			buffer[bytes_used] = '\n';
			bytes_used++;
		}
		if ((bytes_used + 1000) >= sizeof(buffer)) {
			err = kernel_write(filp, buffer, bytes_used,
					&offset);
			if (err < 0) {
				printk(KERN_NOTICE "tt_print_file got "
						"error %d writing %s\n",
						-err, path);
				goto done;
			}
			bytes_used = 0;
		}
	}
	if (bytes_used > 0) {
		err = kernel_write(filp, buffer, bytes_used, &offset);
		if (err < 0)
			printk(KERN_ERR "tt_print_file got error %d "
					"writing %s\n", -err, path);
	}

	printk(KERN_ERR "tt_print_file finishing up\n");
	done:
	if (filp != NULL) {
		err = vfs_fsync(filp, 0);
		if (err < 0)
			printk(KERN_ERR "tt_print_file got error %d "
					"in fsync\n", -err);
		err = filp_close(filp, NULL);
		if (err < 0)
			printk(KERN_ERR "tt_print_file got error %d "
					"in filp_close\n", -err);
	}
	atomic_dec(&tt_freeze_count);
	atomic_set(&active, 0);
	printk(KERN_ERR "tt_print_file(%s) finished\n", path);
}

/**
 * tt_printk() - Print the contents of the timetrace to the system log.
 * Useful in situations where the system is too unstable to extract a
 * timetrace by reading /proc/timetrace.
 */
void tt_printk(void)
{
	/* Index of the next entry to return from each tt_buffer.
	 * This array is too large to allocate on the stack, and we don't
	 * want to allocate space dynamically (this function could be
	 * called at a point where the world is going to hell). So,
	 * allocate the array statically, and only allow one concurrent
	 * call to this function.
	 */
	static int pos[NR_CPUS];
	static atomic_t active;

	if (atomic_xchg(&active, 1)) {
		printk(KERN_NOTICE "concurrent call to tt_printk aborting\n");
		return;
	}
	if (!init)
		return;
	atomic_inc(&tt_freeze_count);
	tt_find_oldest(pos);

	printk(KERN_NOTICE "cpu_khz: %u\n", cpu_khz);

	/* Each iteration of this loop printk's one event. */
	while (true) {
		struct tt_event *event;
		int i;
		int current_core = -1;
		__u64 earliest_time = ~0;
		char msg[200];

		/* Check all the traces to find the earliest available event. */
		for (i = 0; i < nr_cpu_ids; i++) {
			struct tt_buffer *buffer = tt_buffers[i];
			event = &buffer->events[pos[i]];
			if ((pos[i] != buffer->next_index)
					&& (event->timestamp < earliest_time)) {
			    current_core = i;
			    earliest_time = event->timestamp;
			}
		}
		if (current_core < 0) {
		    /* None of the traces have any more events to process. */
		    break;
		}
		event = &(tt_buffers[current_core]->events[
				pos[current_core]]);
		pos[current_core] = (pos[current_core] + 1)
				& (tt_buffer_size-1);

		snprintf(msg, sizeof(msg), event->format, event->arg0,
				event->arg1, event->arg2, event->arg3);
		printk(KERN_NOTICE  "%lu [C%02d] %s\n",
				(long unsigned int) event->timestamp,
				current_core, msg);
	}

	atomic_dec(&tt_freeze_count);
	atomic_set(&active, 0);
}

/**
 * tt_get_messages() - Print the messages from all timetrace records to a
 * caller-provided buffer. Only the messages are printed (no timestamps or
 * core numbers). Intended primarily for use by unit tests.
 * @buffer:    Where to print messages.
 * @length:    Number of bytes available at @buffer; output will be truncated
 *             if needed to fit in this space.
 */
void tt_get_messages(char *buffer, size_t length)
{
	/* Index of the next entry to return from each tt_buffer (too
	 * large to allocate on stack, so allocate dynamically).
	 */
	int *pos = kmalloc(NR_CPUS * sizeof(int), GFP_KERNEL);
	int printed = 0;

	*buffer = 0;
	if (!init)
		goto done;
	atomic_inc(&tt_freeze_count);
	tt_find_oldest(pos);

	/* Each iteration of this loop prints one event. */
	while (true) {
		struct tt_event *event;
		int i, result;
		int current_core = -1;
		__u64 earliest_time = ~0;

		/* Check all the traces to find the earliest available event. */
		for (i = 0; i < nr_cpu_ids; i++) {
			struct tt_buffer *buffer = tt_buffers[i];
			event = &buffer->events[pos[i]];
			if ((pos[i] != buffer->next_index)
					&& (event->timestamp < earliest_time)) {
			    current_core = i;
			    earliest_time = event->timestamp;
			}
		}
		if (current_core < 0) {
		    /* None of the traces have any more events to process. */
		    break;
		}
		event = &(tt_buffers[current_core]->events[
				pos[current_core]]);
		pos[current_core] = (pos[current_core] + 1)
				& (tt_buffer_size-1);

		if (printed > 0) {
			result = snprintf(buffer + printed, length - printed,
					"; ");
			if ((result < 0) || (result >= (length - printed)))
				break;
			printed += result;
		}
		result = snprintf(buffer + printed, length - printed,
				event->format, event->arg0, event->arg1,
				event->arg2, event->arg3);
		if ((result < 0) || (result >= (length - printed)))
			break;
		printed += result;
	}

	atomic_dec(&tt_freeze_count);

	done:
	kfree(pos);
}

/**
 * tt_dbg1() - Invoked by the Linux kernel for various temporary debugging
 * purposes. Arguments are defined as needed for a specific situation.
 */
void tt_dbg1(char *msg, ...)
{
}

/**
 * tt_dbg2() - Invoked by the Linux kernel for various temporary debugging
 * purposes. Arguments are defined as needed for a specific situation.
 */
void tt_dbg2(char *msg, ...)
{
}

/**
 * tt_dbg3() - Invoked by the Linux kernel for various temporary debugging
 * purposes. Arguments are defined as needed for a specific situation.
 */
void tt_dbg3(char *msg, ...)
{
}

/**
 * tt_inc_metric() - Invoked by Linux kernel code to update a
 * Homa metric.
 * @metric:   A value such as TT_NAPI_CYCLES indicating which metric
 *            to increment.
 * @count:    Amount by which to increment to the metric.
 */
void tt_inc_metric(int metric, __u64 count)
{
	/* Maps from the metric argument to an offset within homa_metrics.
	 * This level of indirection is needed so that the kernel doesn't
	 * have to be recompiled every time a new metric gets added (which
	 * can change all of the offsets). See the kernel's timetrace.h
	 * for the legal values of metric.
	 */
	static int offsets[] = {
		offsetof(struct homa_metrics, napi_cycles),
		offsetof(struct homa_metrics, linux_softirq_cycles),
		offsetof(struct homa_metrics, linux_pkt_alloc_bytes),
	};
	__u64 *metric_addr = (__u64 *)(((char *)
			&homa_cores[raw_smp_processor_id()]->metrics)
			+ offsets[metric]);
	*metric_addr += count;
}
