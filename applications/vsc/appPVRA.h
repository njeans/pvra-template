#include <stdbool.h>

#ifndef COMMAND_H
#define COMMAND_H

#define NUM_COMMANDS 2
#define NUM_USERS 2
#define NUM_TESTS 100

struct cInputs
{
	int uid;
	int test_result;
};

struct cResponse
{
	bool access;
	int error;
	char message[100];
};

struct AD
{
	char test_history[NUM_USERS*NUM_TESTS];
	int num_tests[NUM_USERS];
	int query_counter[NUM_USERS];
};

#endif
