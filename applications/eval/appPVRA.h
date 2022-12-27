#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 1
#define NUM_ADMIN_COMMANDS 1

struct userInfo
{
	uint32_t uidx;
};


struct cInputs
{
	uint32_t admin_uidx;
//	uint8_t buff[100];
};

struct cResponse
{
	uint32_t error;
	char message[100];
};

struct AD
{
	struct userInfo *user_info;
};

#endif
