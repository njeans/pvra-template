#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__

#define NUM_COMMANDS 2
#define MAX_TEST 10 //max test history to store
#define MIN_NEG 2 //minimum number of successive negative tests 

struct cInputs
{
	bool test_result;
};

struct cResponse
{
	int error;
	char message[100];
	bool access;
};

struct userTests
{	
	bool test_history[MAX_TEST];
	uint64_t num_tests;
	uint64_t query_counter;
};


struct AD
{
	struct userTests *user_tests;
};

#endif
