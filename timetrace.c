/* Copyright (c) 2019, Stanford University
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

#include "homa_impl.h"

#ifndef __UNIT_TEST__
/* Uncomment the line below if the main Linux kernel has been compiled with
 * timetrace stubs; we will then connect the timetrace mechanism here with
 * those stubs to allow the rest of the kernel to log in our buffers.
 */
// #define TT_KERNEL 1
#endif
#ifdef TT_KERNEL
extern int        tt_linux_buffer_mask;
extern struct tt_buffer *tt_linux_buffers[NR_CPUS];
extern atomic_t * tt_linux_freeze_count;
extern atomic_t   tt_linux_freeze_no_homa;
#endif

/* Separate buffers for each core: this eliminates the need for
 * synchronization in tt_record, which improves performance significantly.
 */
struct tt_buffer *tt_buffers[NR_CPUS];

/* Describes file operations implemented for reading timetraces
 * from /proc.
 */
static const struct file_operations tt_fops = {
	.open		= tt_proc_open,
	.read		= tt_proc_read,
	.release	= tt_proc_release
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
 *             the current timetrace.
 * 
 * Return :    0 means success, anything else means an error occurred (a
 *             log message will be printed to describe the error).
 */
int tt_init(char *proc_file)
{
	int i;
	
	if (init) {
		return 0;
	}

	for (i = 0; i < NR_CPUS; i++) {
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
	
	tt_dir_entry = proc_create(proc_file, S_IRUGO, NULL, &tt_fops);
	if (!tt_dir_entry) {
		printk(KERN_ERR "couldn't create /proc/%s for timetrace "
				"reading\n", proc_file);
		goto error;
	}
	
	spin_lock_init(&tt_lock);
	tt_freeze_count.counter = 0;
	tt_frozen = false;
	init = true;
	
#ifdef TT_KERNEL
	for (i = 0; i < NR_CPUS; i++) {
		tt_linux_buffers[i] = tt_buffers[i];
	}
	tt_linux_buffer_mask = TT_BUF_SIZE-1;
	tt_linux_freeze_count = &tt_freeze_count;
#endif
	
	return 0;
	
	error:
	for (i = 0; i < NR_CPUS; i++) {
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
		proc_remove(tt_dir_entry);
	}
	for (i = 0; i < NR_CPUS; i++) {
		kfree(tt_buffers[i]);
		tt_buffers[i] = NULL;
	}
	tt_freeze_count.counter = 1;
	
#ifdef TT_KERNEL
	tt_linux_freeze_count = &tt_linux_freeze_no_homa;
	for (i = 0; i < NR_CPUS; i++) {
		tt_linux_buffers[i] = NULL;
	}
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
 * tt_proc_open() - This function is invoked when a /proc file is
 * opened to read timetrace info.
 * @inode:    The inode corresponding to the file.
 * @file:     Information about the open file.
 * 
 * Return:    0 for success, else a negative errno.
 */
int tt_proc_open(struct inode *inode, struct file *file)
{
	struct tt_proc_file* pf;
	struct tt_buffer* buffer;
	__u64 start_time;
	int result = 0;
	int i;
	
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
	pf->leftover = NULL;
	pf->num_leftover = 0;
	
	atomic_inc(&tt_freeze_count);
	
	/* Find the oldest event in each trace. This will be events[0]
	 * if we never completely filled the buffer, otherwise
	 * events[nextIndex+1]. This means we don't print the entry at
	 * nextIndex; this is convenient because it simplifies boundary
	 * conditions in the code below.
	 * 
	 * At the same time, find the most recent "oldest time" from
	 * any buffer that has wrapped around (data from earlier than
	 * this isn't necessarily complete, since there may have been
	 * events that were discarded).
	 */
	start_time = 0;
	for (i = 0; i < NR_CPUS; i++) {
		buffer = tt_buffers[i];
		if (buffer->events[tt_buffer_size-1].format == NULL) {
			pf->pos[i] = 0;
		} else {
			int index = (buffer->next_index + 1)
					& (tt_buffer_size-1);
			struct tt_event *event = &buffer->events[index];
			pf->pos[i] = index;
			if (event->timestamp > start_time) {
				start_time = event->timestamp;
			}
		}
	}
	
	/* Skip over all events before start_time, in order to make
	 * sure that there's no missing data in what we print. 
	 */
	for (i = 0; i < NR_CPUS; i++) {
		buffer = tt_buffers[i];
		while ((buffer->events[pf->pos[i]].timestamp < start_time)
				&& (pf->pos[i] != buffer->next_index)) {
			pf->pos[i] = (pf->pos[i] + 1) & (tt_buffer_size-1);
		}
	}
	
	file->private_data = pf;
	
	if (!tt_test_no_khz) {
		pf->num_leftover = snprintf(pf->msg_storage, TT_PF_BUF_SIZE,
				"cpu_khz: %u\n", cpu_khz);
		pf->leftover = pf->msg_storage;
	}
	
	done:
	spin_unlock(&tt_lock);
	return result;
}

/**
 * tt_proc_read() - This function is invoked to handle read kernel calls on
 * /proc files.
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
	int buffered;
	int copied_to_user;
	int result = 0;
	struct tt_proc_file *pf = file->private_data;
	
	spin_lock(&tt_lock);
	if ((pf == NULL) || (pf->file != file)) {
		printk(KERN_ERR "tt_metrics_read found damaged "
				"private_data: 0x%p\n", file->private_data);
		result = -EINVAL;
		goto done;
	}
	
	if (!init) {
		result = 0;
		goto done;
	}
	
	/* Check for leftovers from a previous call. */
	copied_to_user = 0;
	if (pf->num_leftover > 0) {
		copied_to_user = pf->num_leftover;
		if (copied_to_user > length)
			copied_to_user = length;
		if (copy_to_user(user_buf, pf->leftover, copied_to_user) != 0) {
			copied_to_user = -EFAULT;
			goto done;
		}
		pf->leftover += copied_to_user;
		pf->num_leftover -= copied_to_user;
		if (pf->num_leftover > 0) {
			result = copied_to_user;
			goto done;
		}
	}
	
	/* Each iteration through this loop processes one event (the one
	 * with the earliest timestamp). We buffer data until pf->msg_storage
	 * is full, then copy to user space and repeat.
	 */
	buffered = 0;
	while (true) {
		struct tt_event *event;
		int entry_length, bytes_to_copy, available, i;
		int current_core = -1;
		__u64 earliest_time = ~0;

		/* Check all the traces to find the earliest available event. */
		for (i = 0; i < NR_CPUS; i++) {
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
		available = tt_pf_storage - buffered;
		if (available == 0) {
			goto flush;
		}
		entry_length = snprintf(pf->msg_storage + buffered, available,
				"%lu [C%02d] ",
				(long unsigned int) event->timestamp,
			        current_core);
		if (available >= entry_length)
			entry_length += snprintf(
					pf->msg_storage + buffered + entry_length,
					available - entry_length,
					event->format, event->arg0,
					event->arg1, event->arg2, event->arg3);
		if (entry_length >= available) {
			/* Not enough room for this entry. */
			if (buffered == 0) {
				/* Even a full buffer isn't enough for
				 * this entry; truncate the entry. */
				entry_length = available - 1;
			} else {
				goto flush;
			}
		}
		/* Replace terminating null character with newline. */
		pf->msg_storage[buffered + entry_length] = '\n';
		buffered += entry_length + 1;
		pf->pos[current_core] = (pf->pos[current_core] + 1)
				& (tt_buffer_size-1);
		continue;
		
		flush:
		bytes_to_copy = buffered;
		if (bytes_to_copy > (length - copied_to_user)) {
			bytes_to_copy = length - copied_to_user;
		}
		if (bytes_to_copy > 0) {
			if (copy_to_user(user_buf + copied_to_user,
					pf->msg_storage, bytes_to_copy) != 0) {
				copied_to_user = -EFAULT;
				goto done;
			}
		}
		copied_to_user += bytes_to_copy;
		buffered -= bytes_to_copy;
		if ((copied_to_user == length) || (current_core < 0)) {
			pf->num_leftover = buffered;
			pf->leftover = pf->msg_storage + bytes_to_copy;
			break;
		}
	}
	result = copied_to_user;
	
	done:
	spin_unlock(&tt_lock);
	return result;
}

/**
 * tt_proc_release() - This function is invoked when the last reference to
 * an open /proc/net/homa_metrics is closed.  It performs cleanup.
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
			for (i = 0; i < NR_CPUS; i++) {
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