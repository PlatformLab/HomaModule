/* Copyright (c) 2019-2022 Homa Developers
 * SPDX-License-Identifier: BSD-1-Clause
 */

/* Utility functions for unit tests, implemented in C++. */

#ifdef __cplusplus
#define CEXTERN extern "C"
#else
#define CEXTERN extern
#endif

struct unit_hash;

CEXTERN void          unit_fill_data(unsigned char *data, int length,
			int first_value);
CEXTERN void          unit_hash_erase(struct unit_hash *hash, const void *key);
CEXTERN void          unit_hash_free(struct unit_hash *hash);
CEXTERN void         *unit_hash_get(struct unit_hash *hash, const void *key);
CEXTERN struct unit_hash *
                      unit_hash_new(void);
CEXTERN void          unit_hash_set(struct unit_hash *hash, const void *key,
				void *value);
CEXTERN int           unit_hash_size(struct unit_hash *hash);
CEXTERN void          unit_hook(char *id);
CEXTERN void          unit_hook_clear(void);
CEXTERN void          unit_hook_register(void hook_proc(char *id));
CEXTERN void          unit_log_add_separator(char *sep);
CEXTERN void          unit_log_clear(void);
CEXTERN void          unit_log_data(const char *separator, unsigned char *data,
				int length);
CEXTERN int           unit_log_empty(void);
CEXTERN const char   *unit_log_get(void);
CEXTERN void          unit_log_printf(const char *separator,
				const char* format, ...)
				__attribute__((format(printf, 2, 3)));