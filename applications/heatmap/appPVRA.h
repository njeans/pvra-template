#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 1
#define NUM_ADMIN_COMMANDS 1
#define PUBLIC_KEY_SIZE 64
#define HEATMAP_GRANULARITY 10
#define MAX_DATA HEATMAP_GRANULARITY*HEATMAP_GRANULARITY



struct cInputs
{
    float lat;
    float lng;
    uint64_t startTs;
    uint64_t endTs;
    bool result;
};

typedef struct cInputs locationData;

struct cResponse
{
	uint32_t error;
	char message[100];
	uint32_t heatmap_data[HEATMAP_GRANULARITY*HEATMAP_GRANULARITY];
};

struct AD
{
	uint64_t num_data;
	locationData *user_data;
};

#endif
