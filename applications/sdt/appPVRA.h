#include <stdbool.h>
#include "constants.h"

#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 3
#define NUM_ADMIN_COMMANDS 2
#define MERKLE_TREE

#define DATA_SIZE 64
#define ENC_DATA_SIZE 32
#define KEY_SIZE 64
//#define HASH_SIZE 32

#define NUM_COMMANDS 3
#define ADD_DATA 0
#define CANCEL_RET 1
#define GET_DATA 2

#define NUM_ADMIN_COMMANDS 2
#define START_RET 3
#define COMPLETE_RET 4

#define NUM_USERS 5
#define MAX_RETRIEVE 3
#define WAIT_TIME 60 //seconds
#define RESET_TIME 60 //seconds


struct userInfo
{
    uint32_t retrieve_count;
    uint64_t retrieve_time; //time when retrieve can be completed
    uint8_t secret_data[DATA_SIZE];
    bool started_retrieve;
	uint8_t recover_key_hash[HASH_SIZE];
};

struct userLeaf
{
    uint32_t retrieve_count;
    uint64_t retrieve_time; //time when retrieve can be completed
    bool started_retrieve;
	uint32_t uidx;
};

struct cInputs
{
	uint8_t input_data[DATA_SIZE];
	uint8_t recover_key_hash[HASH_SIZE];
	uint8_t recover_key[KEY_SIZE];
	uint8_t user_pubkey[KEY_SIZE];
};

struct cResponse
{
	uint32_t error;
	char message[100];
	uint8_t output_data[DATA_SIZE];
};

struct AD
{
	struct userInfo user_info[NUM_USERS];
	int last_reset_time;
	int retrieve_count;
};

#endif
