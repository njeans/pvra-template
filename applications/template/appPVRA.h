#include <stdbool.h>



#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 1
#define NUM_ADMIN_COMMANDS 0
#define NUM_USERS 4
#define MERKLE_TREE  // todo remove no MERKLE

struct userInfo
{
	uint32_t uidx;
};

#ifdef MERKLE_TREE
struct userLeaf  // todo remove no MERKLE
{
	uint32_t uidx;
};
#endif

struct cInputs
{
	uint32_t admin_uidx;
};

struct cResponse
{
	uint32_t error;
	char message[100];
};

struct AD
{
	struct userInfo * user_info;
};

#endif
