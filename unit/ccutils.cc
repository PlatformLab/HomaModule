/* This file various utility functions for unit testing, which are
 * more conveniently implemented in C++ rather than C. The C++
 * implementation make some things easier, but this file cannot
 * access kernel internal stuff (such as homa_impl.h) because that
 * will cause confusion between kernel-level headers and C++ user-level
 * headers.
 */

#include <cassert>
#include <cstdarg>
#include <string>
#include <unordered_map>

#include <netinet/ip.h>

#include "ccutils.h"

/**
 * Provides simple hash tables for test code written in C.
 */
struct unit_hash {
	std::unordered_map<const void *, void *> map;
};

/* These variables are used during individual unit tests, and are
 * reinitialized for each new test.
 */

/* Accumulates data passed to unit_log_printf */
static std::string log;

/**
 * unit_hash_erase() - Remove an entry from hash table, if it exists.
 * @hash:       The hash table
 * @key:        Key for the entry to remove.
 */
void unit_hash_erase(struct unit_hash *hash, const void *key)
{
	hash->map.erase(key);
}

/**
 * unit_hash_free() - Destructor for hash table; frees its memory.
 * @hash:       Hash table to free; may be NULL.
 */
void unit_hash_free(struct unit_hash *hash)
{
	delete hash;
}

/**
 * unit_hash_get() - Retrieve a value from hash table.
 * @hash:       The hash table
 * @key:        Key for the desired entry
 * 
 * Return:      The value of the entry corresponding to @key, or NULL
 *              if no such entry exists.
 */
void *unit_hash_get(struct unit_hash *hash, const void *key)
{
	std::unordered_map<const void *, void *>::iterator iter =
			hash->map.find(key);
	if (iter == hash->map.end()) {
		return NULL;
	}
	return iter->second;
}

/**
 * unit_hash_new() - Create and return a new empty hash table.
 */
struct unit_hash *unit_hash_new(void)
{
	return new unit_hash;
}

/**
 * unit_hash_set() - Create a new entry in hash table (or overwrite an
 * existing entry, if there was one).
 * @hash:          The hash table
 * @key:           Key for the entry
 * @value:         Value for the entry
 */
void unit_hash_set(struct unit_hash *hash, const void *key, void *value)
{
	hash->map[key] = value;
}

/**
 * hash_size() - Return account of the number of entries in a hash table.
 * @hash:   The hash table (may be NULL).
 */
int unit_hash_size(struct unit_hash *hash)
{
	if (!hash)
		return 0;
	return static_cast<int>(hash->map.size());
}

/**
 * unit_log_clear() - Reset the test log to an empty state.
 */
void unit_log_clear(void)
{
	log.clear();
}

/**
 * unit_fill_data() - Fill in a block of memory with predictable values
 * that can be checked later by unit_log_data.
 * @data:         Address of first byte of data.
 * @length:       Total amount of data, in bytes.
 * @first_value:  Value to store and first 4 bytes of data.
 * 
 * The data area is treated as an array of integers, and filled in with
 * consecutive values starting with first_value. If there are are extra
 * bytes at the end, they are initialized with single-byte values.
 */
void unit_fill_data(unsigned char *data, int length, int first_value)
{ 
	int i;
	for (i = 0; i <= length-4; i += 4) {
		*reinterpret_cast<int32_t *>(data + i) = first_value + i;
	}
	
	/* Fill in extra bytes with low-order-2-decimal-digits. */
	for ( ; i < length; i += 1) {
		data[i] = (first_value + i) % 100;
	}
}

/**
 * unit_log_add_separator() - If the test log has data in it, append a
 * given separator string.
 * @sep:    Separator string.
 */
void unit_log_add_separator(char *sep)
{
	if (!log.empty())
		log.append(sep);
}

/**
 * unit_log_data() - Log information that describes the data provided.
 * @data:      Address of first byte of data.
 * @length:    Total amount of data, in bytes.
 * 
 * This function assumes that the data was written by unit_fill_data.
 */
void unit_log_data(unsigned char *data, int length)
{
	int i, range_start, expected_next;
	const char *separator = "";
	if (length == 0) {
		unit_log_printf("empty block");
		return;
	}
	if (length >= 4)
		range_start = *reinterpret_cast<int32_t *>(data);
	else
		range_start = *data;
	expected_next = range_start;
	for (i = 0; i <= length-4; i += 4) {
		int current = *reinterpret_cast<int32_t *>(data + i);
		if (current != expected_next) {
			unit_log_printf("%s%d-%d", separator, range_start,
				expected_next-1);
			separator = " ";
			range_start = current;
		}
		expected_next = current+4;
	}
	unit_log_printf("%s%d-%d", separator, range_start, expected_next-1);
	separator = " ";
	
	for ( ; i < length; i += 1) {
		unit_log_printf("%s%d", separator, data[i]);
		separator = " ";
	}
}

/**
 * unit_log_empty() - Return nonzero if the log is empty, zero if it has data.
 */
int unit_log_empty(void)
{
	return log.empty() ? 1 : 0;
}

/**
 * unit_get_log() -  Returns the current contents of the test log.
 */
const char *unit_log_get(void)
{
	return log.c_str();
}

/**
 * unit_log_printf() - Append information to the test log.
 * @format:      Standard printf-style format string.
 * @ap:          Additional arguments as required by @format.
 */
void unit_log_printf(const char* format, ...)
{
	va_list ap;
	va_start(ap, format);
	    
	// We're not really sure how big of a buffer will be necessary.
	// Try 1K, if not the return value will tell us how much is necessary.
	int buf_size = 1024;
	while (true) {
		char buf[buf_size];
		// vsnprintf trashes the va_list, so copy it first
		va_list aq;
		__va_copy(aq, ap);
		int length = vsnprintf(buf, buf_size, format, aq);
		assert(length >= 0); // old glibc versions returned -1
		if (length < buf_size) {
			log.append(buf, length);
			break;
		}
		buf_size = length + 1;
	}
	va_end(ap);
}