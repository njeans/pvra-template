#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 4
#define NUM_USERS 2
#define DATA_SIZE 32
#define ENC_DATA_SIZE 32
#define KEY_SIZE 32
#define MAX_RETRIEVE 2
#define WAIT_TIME 60 //seconds
#define RESET_TIME 60 //seconds

struct userInfo
{
    int retrieve_count;
    int retrieve_time; //time when retrieve can be completed
    char secret_data[DATA_SIZE];
    bool started_retrieve;
	int uidx;
};

struct userLeaf
{
    int retrieve_count;
    int retrieve_time; //time when retrieve can be completed
    bool started_retrieve;
};

struct cInputs
{
	int uidx;
	char input_data[DATA_SIZE];
	char recover_key[KEY_SIZE];
};

struct cResponse
{
	int error;
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
