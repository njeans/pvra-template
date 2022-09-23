#include <sgx_tcrypto.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>


#include <stdbool.h>


#ifndef COMMAND_H
#define COMMAND_H

#define NUM_COMMANDS 2
#define NUM_USERS 2
#define NUM_TESTS 100

typedef enum { COMMAND0, COMMAND1 } eType;



struct cType 
{
	int tid;
};



struct cInputs
{
	int uid;
	int test_result;
};

struct clientCommand
{
	struct cType CT;
	struct cInputs CI;
	int seqNo;
	int cid;
};

struct cResponse
{
	bool access;
	int error;
	char message[100];
};


struct AD
{
	char test_history[NUM_USERS][NUM_TESTS];
	int num_tests[NUM_USERS];
	int query_counter[NUM_USERS];
};



#endif
