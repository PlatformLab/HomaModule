/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by the GPLv2 license.
 *
 * kselftest_harness.h: simple C unit test helper.
 *
 * See documentation in Documentation/dev-tools/kselftest.rst
 *
 * API inspired by code.google.com/p/googletest
 */

/**
 * DOC: example
 *
 * .. code-block:: c
 *
 *    #include "../kselftest_harness.h"
 *
 *    TEST(standalone_test) {
 *      do_some_stuff;
 *      EXPECT_GT(10, stuff) {
 *         stuff_state_t state;
 *         enumerate_stuff_state(&state);
 *         TH_LOG("expectation failed with state: %s", state.msg);
 *      }
 *      more_stuff;
 *      ASSERT_NE(some_stuff, NULL) TH_LOG("how did it happen?!");
 *      last_stuff;
 *      EXPECT_EQ(0, last_stuff);
 *    }
 *
 *    FIXTURE(my_fixture) {
 *      mytype_t *data;
 *      int awesomeness_level;
 *    };
 *    FIXTURE_SETUP(my_fixture) {
 *      self->data = mytype_new();
 *      ASSERT_NE(NULL, self->data);
 *    }
 *    FIXTURE_TEARDOWN(my_fixture) {
 *      mytype_free(self->data);
 *    }
 *    TEST_F(my_fixture, data_is_good) {
 *      EXPECT_EQ(1, is_my_data_good(self->data));
 *    }
 *
 *    TEST_HARNESS_MAIN
 */

#ifndef __KSELFTEST_HARNESS_H
#define __KSELFTEST_HARNESS_H

/* This file has been modified considerably from the original version
 * in kernel/tools/testing/selftests in order to allow kernel unit tests
 * to run in user space (by extracting a collection of kernel source files
 * and compiling them into a normal Linux executable along with the
 * unit tests). This creates potential problems with conflicts between
 * kernel header files and user-level header files. To avoid these conflicts,
 * this file must be very careful about what headers it includes. This file
 * is based on a relatively old version of the official file; new versions
 * generate even more header file conflicts, which appear very difficult
 * to resolve.
 * This file also contains several other changes, such as:
 *   - All tests run in a single process, rather than forking a child process
 *     for each test.
 *   - Several unit test files can be compiled separately but linked together
 *     into a single test suite (see KSELFTEST_NOT_MAIN #define).
 */

//#include <stdint.h>
#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>

extern void abort(void);
extern void _exit(int status);
extern int strcmp(const char *s1, const char *s2);


/* Utilities exposed to the test definitions */
#ifndef TH_LOG_STREAM
#  define TH_LOG_STREAM stderr
#endif

#ifndef TH_LOG_ENABLED
#  define TH_LOG_ENABLED 1
#endif

/**
 * TH_LOG(fmt, ...)
 *
 * @fmt: format string
 * @...: optional arguments
 *
 * .. code-block:: c
 *
 *     TH_LOG(format, ...)
 *
 * Optional debug logging function available for use in tests.
 * Logging may be enabled or disabled by defining TH_LOG_ENABLED.
 * E.g., #define TH_LOG_ENABLED 1
 *
 * If no definition is provided, logging is enabled by default.
 *
 * If there is no way to print an error message for the process running the
 * test (e.g. not allowed to write to stderr), it is still possible to get the
 * ASSERT_* number for which the test failed.  This behavior can be enabled by
 * writing `_metadata->no_print = true;` before the check sequence that is
 * unable to print.  When an error occur, instead of printing an error message
 * and calling `abort(3)`, the test process call `_exit(2)` with the assert
 * number as argument, which is then printed by the parent process.
 */
#define TH_LOG(fmt, ...) do { \
	if (TH_LOG_ENABLED) \
		__TH_LOG(fmt, ##__VA_ARGS__); \
} while (0)

/* Unconditional logger for internal use. */
#define __TH_LOG(fmt, ...) \
		fprintf(TH_LOG_STREAM, "%s:%d:%s:" fmt "\n", \
			__FILE__, __LINE__, __current_test->name, ##__VA_ARGS__)

/**
 * FAIL(fmt, ...) - Prints an error message and marks the current test as
 * failed.
 *
 * @fmt: format string
 * @...: optional arguments
 */
#define FAIL(fmt, ...) do { \
	if (TH_LOG_ENABLED) \
		__TH_LOG(fmt, ##__VA_ARGS__); \
	__current_test->passed = 0; \
} while (0)

/**
 * TEST(test_name) - Defines the test function and creates the registration
 * stub
 *
 * @test_name: test name
 *
 * .. code-block:: c
 *
 *     TEST(name) { implementation }
 *
 * Defines a test by name.
 * Names must be unique and tests must not be run in parallel.  The
 * implementation containing block is a function and scoping should be treated
 * as such.  Returning early may be performed with a bare "return;" statement.
 *
 * EXPECT_* and ASSERT_* are valid in a TEST() { } context.
 */
#define TEST(test_name) __TEST_IMPL(test_name, -1)

/**
 * TEST_SIGNAL(test_name, signal)
 *
 * @test_name: test name
 * @signal: signal number
 *
 * .. code-block:: c
 *
 *     TEST_SIGNAL(name, signal) { implementation }
 *
 * Defines a test by name and the expected term signal.
 * Names must be unique and tests must not be run in parallel.  The
 * implementation containing block is a function and scoping should be treated
 * as such.  Returning early may be performed with a bare "return;" statement.
 *
 * EXPECT_* and ASSERT_* are valid in a TEST() { } context.
 */
#define TEST_SIGNAL(test_name, signal) __TEST_IMPL(test_name, signal)

#define __TEST_IMPL(test_name, _signal) \
	static void t_##test_name(struct __test_metadata *_metadata); \
	static struct __test_metadata _##test_name##_object = \
		{ name: "global." #test_name, \
		  fn: &t_##test_name, termsig: _signal }; \
	static void __attribute__((constructor)) _register_##test_name(void) \
	{ \
		__register_test(&_##test_name##_object); \
	} \
	static void t_##test_name( \
		struct __test_metadata __attribute__((unused)) *_metadata)

/**
 * FIXTURE_DATA(datatype_name) - Wraps the struct name so we have one less
 * argument to pass around
 *
 * @datatype_name: datatype name
 *
 * .. code-block:: c
 *
 *     FIXTURE_DATA(datatype name)
 *
 * This call may be used when the type of the fixture data
 * is needed.  In general, this should not be needed unless
 * the *self* is being passed to a helper directly.
 */
#define FIXTURE_DATA(datatype_name) struct _test_data_##datatype_name

/**
 * FIXTURE(fixture_name) - Called once per fixture to setup the data and
 * register
 *
 * @fixture_name: fixture name
 *
 * .. code-block:: c
 *
 *     FIXTURE(datatype name) {
 *       type property1;
 *       ...
 *     };
 *
 * Defines the data provided to TEST_F()-defined tests as *self*.  It should be
 * populated and cleaned up using FIXTURE_SETUP() and FIXTURE_TEARDOWN().
 */
#define FIXTURE(fixture_name) \
	static void __attribute__((constructor)) \
	_register_##fixture_name##_data(void) \
	{ \
		__fixture_count++; \
	} \
	FIXTURE_DATA(fixture_name)

/**
 * FIXTURE_SETUP(fixture_name) - Prepares the setup function for the fixture.
 * *_metadata* is included so that ASSERT_* work as a convenience
 *
 * @fixture_name: fixture name
 *
 * .. code-block:: c
 *
 *     FIXTURE_SETUP(fixture name) { implementation }
 *
 * Populates the required "setup" function for a fixture.  An instance of the
 * datatype defined with FIXTURE_DATA() will be exposed as *self* for the
 * implementation.
 *
 * ASSERT_* are valid for use in this context and will prempt the execution
 * of any dependent fixture tests.
 *
 * A bare "return;" statement may be used to return early.
 */
#define FIXTURE_SETUP(fixture_name) \
	void fixture_name##_setup( \
		struct __test_metadata __attribute__((unused)) *_metadata, \
		FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)
/**
 * FIXTURE_TEARDOWN(fixture_name)
 *
 * @fixture_name: fixture name
 *
 * .. code-block:: c
 *
 *     FIXTURE_TEARDOWN(fixture name) { implementation }
 *
 * Populates the required "teardown" function for a fixture.  An instance of the
 * datatype defined with FIXTURE_DATA() will be exposed as *self* for the
 * implementation to clean up.
 *
 * A bare "return;" statement may be used to return early.
 */
#define FIXTURE_TEARDOWN(fixture_name) \
	void fixture_name##_teardown( \
		struct __test_metadata __attribute__((unused)) *_metadata, \
		FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)

/**
 * TEST_F(fixture_name, test_name) - Emits test registration and helpers for
 * fixture-based test cases
 *
 * @fixture_name: fixture name
 * @test_name: test name
 *
 * .. code-block:: c
 *
 *     TEST_F(fixture, name) { implementation }
 *
 * Defines a test that depends on a fixture (e.g., is part of a test case).
 * Very similar to TEST() except that *self* is the setup instance of fixture's
 * datatype exposed for use by the implementation.
 */
/* TODO(wad) register fixtures on dedicated test lists. */
#define TEST_F(fixture_name, test_name) \
	__TEST_F_IMPL(fixture_name, test_name, -1)

#define TEST_F_SIGNAL(fixture_name, test_name, signal) \
	__TEST_F_IMPL(fixture_name, test_name, signal)

#define __TEST_F_IMPL(fixture_name, test_name, signal) \
	static void fixture_name##_##test_name( \
		struct __test_metadata *_metadata, \
		FIXTURE_DATA(fixture_name) *self); \
	static inline void wrapper_##fixture_name##_##test_name( \
		struct __test_metadata *_metadata) \
	{ \
		/* fixture data is alloced, setup, and torn down per call. */ \
		FIXTURE_DATA(fixture_name) self; \
		memset(&self, 0, sizeof(FIXTURE_DATA(fixture_name))); \
		fixture_name##_setup(_metadata, &self); \
		/* Let setup failure terminate early. */ \
		if (!_metadata->passed) \
			return; \
		fixture_name##_##test_name(_metadata, &self); \
		fixture_name##_teardown(_metadata, &self); \
	} \
	static struct __test_metadata \
		      _##fixture_name##_##test_name##_object = { \
		name: #fixture_name "." #test_name, \
		fn: &wrapper_##fixture_name##_##test_name, \
		termsig: signal, \
	 }; \
	static void __attribute__((constructor)) \
			_register_##fixture_name##_##test_name(void) \
	{ \
		__register_test(&_##fixture_name##_##test_name##_object); \
	} \
	static void fixture_name##_##test_name( \
		struct __test_metadata __attribute__((unused)) *_metadata, \
		FIXTURE_DATA(fixture_name) __attribute__((unused)) *self)

/**
 * DOC: operators
 *
 * Operators for use in TEST() and TEST_F().
 * ASSERT_* calls will stop test execution immediately.
 * EXPECT_* calls will emit a failure warning, note it, and continue.
 */

/**
 * ASSERT_EQ(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_EQ(expected, measured): expected == measured
 */
#define ASSERT_EQ(expected, seen) \
	__EXPECT(expected, seen, ==, return)

#define INET6_ADDRSTRLEN 46

#define EXPECT_EQ_IP(a, b) \
	do { \
		struct in6_addr _a1 = (a), _a2 = (b); \
		char buf1[INET6_ADDRSTRLEN+2], buf2[INET6_ADDRSTRLEN+2]; \
		strncpy(buf1, homa_print_ipv6_addr(&_a1), sizeof(buf1)); \
		strncpy(buf2, homa_print_ipv6_addr(&_a2), sizeof(buf2)); \
		EXPECT_STREQ(buf1, buf2); \
	} while(0)
/**
 * ASSERT_NE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_NE(expected, measured): expected != measured
 */
#define ASSERT_NE(expected, seen) \
	__EXPECT(expected, seen, !=, return)

/**
 * ASSERT_LT(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_LT(expected, measured): expected < measured
 */
#define ASSERT_LT(expected, seen) \
	__EXPECT(expected, seen, <, return)

/**
 * ASSERT_LE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_LE(expected, measured): expected <= measured
 */
#define ASSERT_LE(expected, seen) \
	__EXPECT(expected, seen, <=, return)

/**
 * ASSERT_GT(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_GT(expected, measured): expected > measured
 */
#define ASSERT_GT(expected, seen) \
	__EXPECT(expected, seen, >, return)

/**
 * ASSERT_GE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_GE(expected, measured): expected >= measured
 */
#define ASSERT_GE(expected, seen) \
	__EXPECT(expected, seen, >=, return)

/**
 * ASSERT_NULL(seen)
 *
 * @seen: measured value
 *
 * ASSERT_NULL(measured): NULL == measured
 */
#define ASSERT_NULL(seen) \
	__EXPECT(NULL, seen, ==, return)

/**
 * ASSERT_TRUE(seen)
 *
 * @seen: measured value
 *
 * ASSERT_TRUE(measured): measured != 0
 */
#define ASSERT_TRUE(seen) \
	ASSERT_NE(0, seen)

/**
 * ASSERT_FALSE(seen)
 *
 * @seen: measured value
 *
 * ASSERT_FALSE(measured): measured == 0
 */
#define ASSERT_FALSE(seen) \
	ASSERT_EQ(0, seen)

/**
 * ASSERT_STREQ(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_STREQ(expected, measured): !strcmp(expected, measured)
 */
#define ASSERT_STREQ(expected, seen) \
	__EXPECT_STR(expected, seen, ==, return)

/**
 * ASSERT_STRNE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * ASSERT_STRNE(expected, measured): strcmp(expected, measured)
 */
#define ASSERT_STRNE(expected, seen) \
	__EXPECT_STR(expected, seen, !=, return)

/**
 * ASSERT_SUBSTR(expected, seen)
 *
 * @expected: value expected as a substring of @seen
 * @seen: measured value
 *
 * ASSERT_SUBSTR(expected, measured): strstr(measured, expected) != NULL
 */
#define ASSERT_SUBSTR(expected, seen) \
	__EXPECT_SUBSTR(expected, seen, return)

/**
 * ASSERT_NOSUBSTR(expected, seen)
 *
 * @expected: value not expected to appear as a substring of @seen
 * @seen: measured value
 *
 * ASSERT_NOSUBSTR(expected, measured): strstr(measured, expected) == NULL
 */
#define ASSERT_NOSUBSTR(expected, seen) \
	__EXPECT_NOSUBSTR(expected, seen, return)

/**
 * EXPECT_EQ(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_EQ(expected, measured): expected == measured
 */
#define EXPECT_EQ(expected, seen) \
	__EXPECT(expected, seen, ==, NULL)

/**
 * EXPECT_NE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_NE(expected, measured): expected != measured
 */
#define EXPECT_NE(expected, seen) \
	__EXPECT(expected, seen, !=, NULL)

/**
 * EXPECT_LT(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_LT(expected, measured): expected < measured
 */
#define EXPECT_LT(expected, seen) \
	__EXPECT(expected, seen, <, NULL)

/**
 * EXPECT_LE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_LE(expected, measured): expected <= measured
 */
#define EXPECT_LE(expected, seen) \
	__EXPECT(expected, seen, <=, NULL)

/**
 * EXPECT_GT(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_GT(expected, measured): expected > measured
 */
#define EXPECT_GT(expected, seen) \
	__EXPECT(expected, seen, >, NULL)

/**
 * EXPECT_GE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_GE(expected, measured): expected >= measured
 */
#define EXPECT_GE(expected, seen) \
	__EXPECT(expected, seen, >=, NULL)

/**
 * EXPECT_NULL(seen)
 *
 * @seen: measured value
 *
 * EXPECT_NULL(measured): NULL == measured
 */
#define EXPECT_NULL(seen) \
	__EXPECT(NULL, seen, ==, NULL)

/**
 * EXPECT_TRUE(seen)
 *
 * @seen: measured value
 *
 * EXPECT_TRUE(measured): 0 != measured
 */
#define EXPECT_TRUE(seen) \
	EXPECT_NE(0, seen)

/**
 * EXPECT_FALSE(seen)
 *
 * @seen: measured value
 *
 * EXPECT_FALSE(measured): 0 == measured
 */
#define EXPECT_FALSE(seen) \
	EXPECT_EQ(0, seen)

/**
 * EXPECT_STREQ(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_STREQ(expected, measured): !strcmp(expected, measured)
 */
#define EXPECT_STREQ(expected, seen) \
	__EXPECT_STR(expected, seen, ==, NULL)

/**
 * EXPECT_STRNE(expected, seen)
 *
 * @expected: expected value
 * @seen: measured value
 *
 * EXPECT_STRNE(expected, measured): strcmp(expected, measured)
 */
#define EXPECT_STRNE(expected, seen) \
	__EXPECT_STR(expected, seen, !=, NULL)

/**
 * EXPECT_SUBSTR(expected, seen)
 *
 * @expected: value expected as a substring of @seen
 * @seen: measured value
 *
 * EXPECT_SUBSTR(expected, measured): strstr(measured, expected) != NULL
 */
#define EXPECT_SUBSTR(expected, seen) \
	__EXPECT_SUBSTR(expected, seen, NULL)

/**
 * EXPECT_NOSUBSTR(expected, seen)
 *
 * @expected: value not expected to appear as a substring of @seen
 * @seen: measured value
 *
 * EXPECT_NOSUBSTR(expected, measured): strstr(measured, expected) == NULL
 */
#define EXPECT_NOSUBSTR(expected, seen) \
	__EXPECT_NOSUBSTR(expected, seen, NULL)

#define __INC_STEP(_metadata) \
	if (_metadata->passed && _metadata->step < 255) \
		_metadata->step++;

#define __EXPECT(_expected, _seen, _t, return_or_NULL) do { \
	/* Avoid multiple evaluation of the cases */ \
	__typeof__(_expected) __exp = (_expected); \
	__typeof__(_seen) __seen = (_seen); \
	__INC_STEP(__current_test); \
	if (!(__exp _t __seen)) { \
		unsigned long long __exp_print = (long long)__exp; \
		unsigned long long __seen_print = (long long)__seen; \
		__TH_LOG(" Expected %s (%llu) %s %s (%llu)", \
			 #_expected, __exp_print, #_t, \
			 #_seen, __seen_print); \
		__current_test->passed = 0; \
		/* Ensure the optional handler is triggered */ \
		__current_test->trigger = 1; \
		return_or_NULL; \
	} \
} while (0)

#define __EXPECT_STR(_expected, _seen, _t, return_or_NULL) do { \
	const char *__exp = (_expected); \
	const char *__seen = (_seen); \
	__INC_STEP(_metadata); \
	if (!(strcmp(__exp, __seen) _t 0))  { \
		__TH_LOG(" Expected '%s' %s '%s'.", __exp, #_t, __seen); \
		_metadata->passed = 0; \
		_metadata->trigger = 1; \
		return_or_NULL; \
	} \
} while (0)

#define __EXPECT_SUBSTR(_expected, _seen, return_or_NULL) do { \
	const char *__exp = (_expected); \
	const char *__seen = (_seen); \
	__INC_STEP(_metadata); \
	if (!strstr( __seen, __exp))  { \
		__TH_LOG(" Expected '%s' in '%s'.", __exp, __seen); \
		_metadata->passed = 0; \
		_metadata->trigger = 1; \
		return_or_NULL; \
	} \
} while (0)

#define __EXPECT_NOSUBSTR(_expected, _seen, return_or_NULL) do { \
	const char *__exp = (_expected); \
	const char *__seen = (_seen); \
	__INC_STEP(_metadata); \
	if (strstr( __seen, __exp))  { \
		__TH_LOG(" Expected no '%s' in '%s'.", __exp, __seen); \
		_metadata->passed = 0; \
		_metadata->trigger = 1; \
		return_or_NULL; \
	} \
} while (0)

/* Contains all the information for test execution and status checking. */
struct __test_metadata {
	const char *name;
	void (*fn)(struct __test_metadata *);
	int termsig;
	int passed;
	int trigger; /* extra handler after the evaluation */
	unsigned char step;
	int no_print; /* manual trigger when TH_LOG_STREAM is not available */
	struct __test_metadata *prev, *next;
};


extern struct __test_metadata *__test_list;
extern struct __test_metadata *__current_test;
extern unsigned int __test_count;
extern unsigned int __fixture_count;
extern int __constructor_order;

#define _CONSTRUCTOR_ORDER_FORWARD   1
#define _CONSTRUCTOR_ORDER_BACKWARD -1

/*
 * Since constructors are called in reverse order, reverse the test
 * list so tests are run in source declaration order.
 * https://gcc.gnu.org/onlinedocs/gccint/Initialization.html
 * However, it seems not all toolchains do this correctly, so use
 * __constructor_order to detect which direction is called first
 * and adjust list building logic to get things running in the right
 * direction.
 */
static inline void __register_test(struct __test_metadata *t)
{
	__test_count++;
	/* Circular linked list where only prev is circular. */
	if (__test_list == NULL) {
		__test_list = t;
		t->next = NULL;
		t->prev = t;
		return;
	}
	if (__constructor_order == _CONSTRUCTOR_ORDER_FORWARD) {
		t->next = NULL;
		t->prev = __test_list->prev;
		t->prev->next = t;
		__test_list->prev = t;
	} else {
		t->next = __test_list;
		t->next->prev = t;
		t->prev = t;
		__test_list = t;
	}
}

#if 0
static inline int __bail(int for_realz, int no_print, unsigned char step)
{
	if (for_realz) {
		if (no_print)
			_exit(step);
		abort();
	}
	return 0;
}
#endif

#ifndef KSELFTEST_NOT_MAIN

/* Storage for the (global) tests to be run. */
struct __test_metadata *__test_list;
struct __test_metadata *__current_test;
unsigned int __test_count;
unsigned int __fixture_count;
int __constructor_order;
static int __verbose = 0;

void __run_test(struct __test_metadata *t)
{
	__current_test = t;
	t->passed = 1;
	t->trigger = 0;
	if (__verbose)
		printf("[ RUN      ] %s\n", t->name);
	t->fn(t);
#if 0
	child_pid = fork();
	if (child_pid < 0) {
		printf("ERROR SPAWNING TEST CHILD\n");
		t->passed = 0;
	} else if (child_pid == 0) {
		t->fn(t);
		/* return the step that failed or 0 */
		_exit(t->passed ? 0 : t->step);
	} else {
		/* TODO(wad) add timeout support. */
		waitpid(child_pid, &status, 0);
		if (WIFEXITED(status)) {
			t->passed = t->termsig == -1 ? !WEXITSTATUS(status) : 0;
			if (t->termsig != -1) {
				fprintf(TH_LOG_STREAM,
					"%s: Test exited normally "
					"instead of by signal (code: %d)\n",
					t->name,
					WEXITSTATUS(status));
			} else if (!t->passed) {
				fprintf(TH_LOG_STREAM,
					"%s: Test failed at step #%d\n",
					t->name,
					WEXITSTATUS(status));
			}
		} else if (WIFSIGNALED(status)) {
			t->passed = 0;
			if (WTERMSIG(status) == SIGABRT) {
				fprintf(TH_LOG_STREAM,
					"%s: Test terminated by assertion\n",
					t->name);
			} else if (WTERMSIG(status) == t->termsig) {
				t->passed = 1;
			} else {
				fprintf(TH_LOG_STREAM,
					"%s: Test terminated unexpectedly "
					"by signal %d\n",
					t->name,
					WTERMSIG(status));
			}
		} else {
			fprintf(TH_LOG_STREAM,
				"%s: Test ended in some other way [%u]\n",
				t->name,
				status);
		}
	}
#endif
	if (!t->passed)
		fprintf(TH_LOG_STREAM, "%s: Test failed at step #%d\n",
			t->name, t->step);
	if (!t->passed || __verbose)
		printf("[     %4s ] %s\n", (t->passed ? "OK" : "FAIL"),
			t->name);
}

/**
 * test_harness_run() - Run tests
 * @argc:    Number of elements in argv; if > 0, then only tests with names
 *           matching one of the elements in argv will be executed.
 * @argv:    Test names.
 * @verbose: Nonzero means print all test names as they run; zero means print
 *           only for test failures.
 */
static int test_harness_run(int  argc, char  **argv, int verbose)
{
	struct __test_metadata *t;
	int ret = 0;
	unsigned int count = 0;
	unsigned int pass_count = 0;
	__verbose = verbose;

	printf("[==========] %u tests available from %u test cases.\n",
	       __test_count, __fixture_count + 1);
	for (t = __test_list; t; t = t->next) {
		if (argc > 0) {
			int i;
			for (i = 0; i < argc; i++) {
				if (strcmp(argv[i], t->name) == 0)
					break;
			}
			if (i >= argc)
				continue;
		}
		count++;
		__run_test(t);
		if (t->passed)
			pass_count++;
		else
			ret = 1;
	}
	printf("[==========] %u / %u tests passed.\n", pass_count, count);
	printf("[  %s  ]\n", (ret ? "FAILED" : "PASSED"));
	return ret;
}
#endif  /* KSELFTEST_NOT_MAIN */

static void __attribute__((constructor)) __constructor_order_first(void)
{
	if (!__constructor_order)
		__constructor_order = _CONSTRUCTOR_ORDER_FORWARD;
}

static void __attribute__((constructor)) __constructor_order_second(void)
{
	if (!__constructor_order)
		__constructor_order = _CONSTRUCTOR_ORDER_BACKWARD;
}

#endif  /* __KSELFTEST_HARNESS_H */
