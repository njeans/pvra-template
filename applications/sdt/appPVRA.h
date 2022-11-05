#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 3
#define NUM_ADMIN_COMMANDS 2
#define NUM_USERS 5
#define DATA_SIZE 64
#define ENC_DATA_SIZE 32
#define KEY_SIZE 64
#define MAX_RETRIEVE 3
#define WAIT_TIME 60 //seconds
#define RESET_TIME 60 //seconds
#define MERKLE_TREE

struct userInfo
{
    uint32_t retrieve_count;
    uint64_t retrieve_time; //time when retrieve can be completed
    char secret_data[DATA_SIZE];
    bool started_retrieve;
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
	char input_data[DATA_SIZE];
	char recover_key[KEY_SIZE];
	char user_pubkey[KEY_SIZE];
};

struct cResponse
{
	uint32_t error;
	char message[100];
	char output_data[DATA_SIZE];
};

struct AD
{
	struct userInfo user_info[NUM_USERS];
	int last_reset_time;
	int retrieve_count;
};

#endif
