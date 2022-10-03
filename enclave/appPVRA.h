#include <stdbool.h>

#define INITSEALSIZE 7024

#ifndef COMMAND_H
#define COMMAND_H


#define NUM_COMMANDS 2
#define NUM_USERS 2
#define PUBLIC_KEY_SIZE 64

#define  HEATMAP_GRANULARITY 5



struct locationData
{
    float lat;
    float lng;
    int startTs;
    int endTs;
    bool result;
};
//
//struct heatmapEntry
//{
//    int latLoc;
//    int lngLoc;
//    int count;
//};

struct cInputs
{
	int uid;
	struct locationData data;
};

struct cResponse
{
	int error;
	char message[100];
	int heatmap_data[HEATMAP_GRANULARITY*HEATMAP_GRANULARITY];
};

struct AD
{
	char user_info[NUM_USERS*PUBLIC_KEY_SIZE];
	int num_data;
	struct locationData *user_data;
};



#endif
