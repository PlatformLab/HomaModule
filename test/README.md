This directory contains unit tests for the Homa Linux kernel module.
Here are a few overall notes:

* These are "white box" tests, not "black box" tests. Tests are written
  by looking at the code and writing enough tests to make sure all of the
  major code elements are covered.

* The structure of the unit tests is isomorphic to the structure of the
  code:
  * There is one test file in this directory for each code file. For example,
    `unit_homa_incoming.c` contains unit tests for `../homa_incoming.c`.
  * Within the test file, there is a block of tests for each function in the
    corresponding code file, and the test blocks occur in the same order
    as the functions. If you move functions around, move the tests around
    to maintain isomorphism.
  * The tests for each function are ordered according to which lines of code
    in the function they test. Typically, a given test will test one or a few
    lines of the function. The order of the tests matches the order of the
    code ranges they test. With this approach, it's easy to scan the tests
    for a function after you make changes the see if you need to add more
    tests.
  * Some functions will have an initial test labeled "basic" or "sanity check".
    These initial tests may exercise a variety of features in the function;
    remaining tests only need to cover things not exercised by the initial
    test.

* The name of a test indicates what function it is testing, and also gives
  a very terse synopsis of what is being tested. For example, consider this
  test from `homa_incoming.c`:
  ```
  TEST_F(homa_incoming, homa_add_packet__packet_overlaps_message_end)
  {
    ...
  }
  ```
  The name of the test is `homa_add_packet__packet_overlaps_message_end`;
  the test exercises the function `homa_add_packet`, and the particular
  case is a new arriving packet that extends past the end of the message.

* In general, tests should be disaggregated so that each test only tests a small
  amount of functionality. Avoid large tests that test many different things.

* In writing tests, focus on the control structure. For example, there should
  be tests for each branch of an `if` statement. For loops, be sure to
  include tests that involve multiple iterations of the loop.

* You don't need to individually test each side effect of a collection of
  straight-line statements; testing one or two of them is fine.

* The file `mock.c` mocks out Linux kernel functions invoked by the code
  being tested. Where relevant, the mocking code may record information about
  how it was invoked and/or allow for the injection of errors in results.

* It should be possible to exercise virtually every line of code in Homa.
  If it appears that you cannot exercise a particular line, check to see
  whether `mock.c` has mechanisms you can use to get the desired effect.
  If not, consider extending `mock.c` to provide whatever you need.

* Feel free to contact John Ousterhout if you're having trouble figuring out
  how to test a particular piece of code.
