#include "homa_impl.h"
#define KSELFTEST_NOT_MAIN 1
#include "kselftest_harness.h"
#include "ccutils.h"
#include "mock.h"
#include "utils.h"

FIXTURE(timetrace) {
	struct file file;
};
FIXTURE_SETUP(timetrace)
{
	self->file.private_data = 0;
	tt_buffer_size = 64;
	tt_test_no_khz = true;
	tt_init("tt");
	mock_cycles = 1000;
}
FIXTURE_TEARDOWN(timetrace)
{
	if (self->file.private_data)
		tt_proc_release(NULL, &self->file);
	tt_destroy();
	tt_test_no_khz = false;
	tt_buffer_size = TT_BUF_SIZE;
	tt_pf_storage = TT_PF_BUF_SIZE;
	unit_teardown();
}

TEST_F(timetrace, tt_freeze)
{
	EXPECT_EQ(0, tt_freeze_count.counter);
	tt_freeze();
	EXPECT_EQ(1, tt_freeze_count.counter);
	EXPECT_TRUE(tt_frozen);
	tt_freeze();
	EXPECT_EQ(1, tt_freeze_count.counter);
	EXPECT_TRUE(tt_frozen);
}

TEST_F(timetrace, tt_record__basics)
{
	tt_record("Message with no args");
	mock_cycles++;
	tt_record1("Message with 1 arg: %d", 99);
	mock_cycles++;
	tt_record2("Message with 2 args: %d %d %d %d", 100, 200);
	mock_cycles++;
	tt_record3("Message with 3 args: %d %d %d %d", 10, 20, 30);
	mock_cycles++;
	tt_record4("Message with 4 args: %d %d %d %d", 1, 2, 3, 4);
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 500, 0);
	tt_proc_release(NULL, &self->file);
	EXPECT_STREQ("1000 [core  1] Message with no args\n"
			"1001 [core  1] Message with 1 arg: 99\n"
			"1002 [core  1] Message with 2 args: 100 200 0 0\n"
			"1003 [core  1] Message with 3 args: 10 20 30 0\n"
			"1004 [core  1] Message with 4 args: 1 2 3 4\n",
			mock_user_data);
}

TEST_F(timetrace, tt_record_buf__wraparound)
{
	tt_buffer_size = 4;
	tt_record("Message 1");
	mock_cycles++;
	tt_record("Message 2");
	mock_cycles++;
	tt_record("Message 3");
	mock_cycles++;
	tt_record("Message 4");
	mock_cycles++;
	tt_record("Message 5");
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 500, 0);
	tt_proc_release(NULL, &self->file);
	EXPECT_STREQ("1002 [core  1] Message 3\n"
			"1003 [core  1] Message 4\n"
			"1004 [core  1] Message 5\n", mock_user_data);
}

TEST_F(timetrace, tt_proc_open__not_initialized)
{
	tt_destroy();
	int err = -tt_proc_open(NULL, &self->file);
	EXPECT_EQ(EINVAL, err);
}
TEST_F(timetrace, tt_proc_open__no_memory)
{
	mock_kmalloc_errors = 1;
	int err = -tt_proc_open(NULL, &self->file);
	EXPECT_EQ(ENOMEM, err);
}
TEST_F(timetrace, tt_proc_open__compute_start_time_and_skip_events)
{
	tt_buffer_size = 4;
	
	tt_record_buf(tt_buffers[0], 1500, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1600, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1700, "Buf0", 0, 0, 0, 0);
	
	tt_record_buf(tt_buffers[1], 1000, "Buf1", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1100, "Buf1", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1200, "Buf1", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1300, "Buf1", 0, 0, 0, 0);
	
	tt_record_buf(tt_buffers[2], 1100, "Buf2", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[2], 1150, "Buf2", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[2], 1160, "Buf2", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[2], 1210, "Buf2", 0, 0, 0, 0);
	
	tt_record_buf(tt_buffers[3], 1000, "Buf3", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[3], 1400, "Buf3", 0, 0, 0, 0);
	
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 500, 0);
	tt_proc_release(NULL, &self->file);
	EXPECT_STREQ("1150 [core  2] Buf2\n"
			"1160 [core  2] Buf2\n"
			"1200 [core  1] Buf1\n"
			"1210 [core  2] Buf2\n"
			"1300 [core  1] Buf1\n"
			"1400 [core  3] Buf3\n"
			"1500 [core  0] Buf0\n"
			"1600 [core  0] Buf0\n"
			"1700 [core  0] Buf0\n", mock_user_data);
}
TEST_F(timetrace, tt_proc_open__increment_frozen)
{
	tt_proc_open(NULL, &self->file);
	EXPECT_EQ(1, tt_freeze_count.counter);
}

TEST_F(timetrace, tt_proc_read__bogus_file)
{
	struct tt_proc_file pf;
	pf.file = NULL;
	int err = -tt_proc_read(&self->file, (char *) 1000, 100, 0);
	EXPECT_EQ(EINVAL, err);
	self->file.private_data = &pf;
	err = -tt_proc_read(&self->file, (char *) 1000, 100, 0);
	EXPECT_EQ(EINVAL, err);
	self->file.private_data = NULL;
}
TEST_F(timetrace, tt_proc_read__uninitialized)
{
	tt_proc_open(NULL, &self->file);
	tt_destroy();
	int result = tt_proc_read(&self->file, (char *) 1000, 100, 0);
	EXPECT_EQ(0, result);
}
TEST_F(timetrace, tt_proc_read__nothing_to_read)
{
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 20, 0);
	EXPECT_STREQ("", mock_user_data);
	tt_proc_release(NULL, &self->file);
}
TEST_F(timetrace, tt_proc_read__leftovers)
{
	tt_pf_storage = 100;
	tt_record_buf(tt_buffers[0], 1000,
			"AAAA BBBB CCCC DDDD EEEE FFFF "
			"GGGG HHHH IIII JJJJ KKKK LLLL "
			"MMMM NNNN OOOO PPPP", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1001,
			"0000 1111 2222 3333 4444 5555 "
			"6666 7777", 0, 0, 0, 0);
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 20, 0);
	EXPECT_STREQ("1000 [core  0] AAAA ", mock_user_data);
	tt_proc_read(&self->file, (char*) 1000, 40, 0);
	EXPECT_STREQ("BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII ",
			mock_user_data);
	tt_proc_read(&self->file, (char*) 1000, 200, 0);
	EXPECT_STREQ("JJJJ KKKK LLLL MMMM NNNN OOOO PPPP\n"
			"1001 [core  0] 0000 1111 2222 3333 4444 "
			"5555 6666 7777\n", mock_user_data);
	tt_proc_release(NULL, &self->file);
}
TEST_F(timetrace, tt_proc_read__sort_events_by_time)
{	
	tt_record_buf(tt_buffers[0], 1000, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1100, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1200, "Buf1", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[2], 1300, "Buf2", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[3], 1400, "Buf3", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[3], 1500, "Buf3", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[3], 1600, "Buf3", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1700, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1800, "Buf1", 0, 0, 0, 0);
	
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 500, 0);
	tt_proc_release(NULL, &self->file);
	EXPECT_STREQ("1000 [core  0] Buf0\n"
		"1100 [core  0] Buf0\n"
		"1200 [core  1] Buf1\n"
		"1300 [core  2] Buf2\n"
		"1400 [core  3] Buf3\n"
		"1500 [core  3] Buf3\n"
		"1600 [core  3] Buf3\n"
		"1700 [core  0] Buf0\n"
		"1800 [core  1] Buf1\n", mock_user_data);
}
TEST_F(timetrace, tt_proc_read__event_barely_fits_in_buffer)
{
	tt_pf_storage = 25;
	tt_record_buf(tt_buffers[0], 1000,
			"AAAA BBBB", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1001,
			"EEEE FFFF", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[0], 1002,
			"IIII JJJJ", 0, 0, 0, 0);
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 100, 0);
	EXPECT_STREQ("1000 [core  0] AAAA BBBB\n"
		"1001 [core  0] EEEE FFFF\n"
		"1002 [core  0] IIII JJJJ\n", mock_user_data);
	tt_proc_release(NULL, &self->file);
}
TEST_F(timetrace, tt_proc_read__single_entry_too_large)
{
	tt_pf_storage = 20;
	tt_record_buf(tt_buffers[0], 1000,
			"AAAA BBBB CCCC DDDD", 0, 0, 0, 0);
	tt_proc_open(NULL, &self->file);
	tt_proc_read(&self->file, (char*) 1000, 100, 0);
	EXPECT_STREQ("1000 [core  0] AAAA\n", mock_user_data);
	tt_proc_release(NULL, &self->file);
}

TEST_F(timetrace, tt_proc_release__bogus_file)
{
	struct tt_proc_file pf;
	pf.file = NULL;
	int err = -tt_proc_release(NULL, &self->file);
	EXPECT_EQ(EINVAL, err);
	self->file.private_data = &pf;
	err = -tt_proc_release(NULL, &self->file);
	EXPECT_EQ(EINVAL, err);
	self->file.private_data = NULL;
}
TEST_F(timetrace, tt_proc_release__unfreeze)
{
	struct file file2;
	
	tt_buffer_size = 4;
	tt_record_buf(tt_buffers[1], 1000, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1100, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1200, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1300, "Buf0", 0, 0, 0, 0);
	tt_record_buf(tt_buffers[1], 1400, "Buf0", 0, 0, 0, 0);
	
	tt_freeze();
	tt_proc_open(NULL, &self->file);
	EXPECT_EQ(2, tt_freeze_count.counter);
	EXPECT_TRUE(tt_frozen);
	tt_proc_open(NULL, &file2);
	EXPECT_EQ(3, tt_freeze_count.counter);
	EXPECT_TRUE(tt_frozen);
	
	tt_proc_release(NULL, &self->file);
	EXPECT_EQ(2, tt_freeze_count.counter);
	EXPECT_TRUE(tt_frozen);
	EXPECT_NE(NULL, tt_buffers[1]->events[3].format);
	EXPECT_EQ(2, tt_buffers[1]->next_index);
	
	tt_proc_release(NULL, &file2);
	EXPECT_EQ(0, tt_freeze_count.counter);
	EXPECT_FALSE(tt_frozen);
	EXPECT_EQ(NULL, tt_buffers[1]->events[3].format);
	EXPECT_EQ(0, tt_buffers[1]->next_index);
}