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
	std::unordered_map<void *, void *> map;
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
void unit_hash_erase(struct unit_hash *hash, void *key)
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
void *unit_hash_get(struct unit_hash *hash, void *key)
{
	std::unordered_map<void *, void *>::iterator iter = hash->map.find(key);
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
void unit_hash_set(struct unit_hash *hash, void *key, void *value)
{
	hash->map[key] = value;
}

/**
 * hash_size() - Return account of the number of entries in a hash table.
 * @hash:   The hash table
 */
int unit_hash_size(struct unit_hash *hash)
{
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