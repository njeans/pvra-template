#include <stdbool.h>



#ifndef COMMAND_H
#define COMMAND_H


#define NUM_COMMANDS 2
#define NUM_USERS 2
#define PUBLIC_KEY_SIZE 64

int HEATMAP_GRANULARITY = 5;

struct cInputs
{
	int uid;
	int num_data;
	locationData[] data;
};

struct locationData
{
    float lat;
    float lng;
    int startTs;
    int endTs;
    bool result;
};

struct cResponse
{
	int error;
	char error_message[100];
	heatmapEntry heatmap[HEATMAP_GRANULARITY*HEATMAP_GRANULARITY];
};

struct heatmapEntry
{
    int latLoc;
    int lngLoc;
    int count;
};


struct AD
{
	char user_info[NUM_USERS*PUBLIC_KEY_SIZE];
	int num_data
	struct locationData * user_data;
};



#endif
