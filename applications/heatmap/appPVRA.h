#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 1
#define NUM_ADMIN_COMMANDS 1
#define NUM_USERS 4
#define PUBLIC_KEY_SIZE 64
#define HEATMAP_GRANULARITY 10
#define MAX_DATA 100



struct locationData
{
    float lat;
    float lng;
    uint64_t startTs;
    uint64_t endTs;
    bool result;
};

struct cInputs
{
    float lat;
    float lng;
    uint64_t startTs;
    uint64_t endTs;
    bool result;
};


struct cResponse
{
	uint32_t error;
	char message[100];
	uint32_t heatmap_data[HEATMAP_GRANULARITY*HEATMAP_GRANULARITY];
};

struct AD
{
	char *user_info;
	int num_data;
	struct cInputs *user_data;
};

#endif
