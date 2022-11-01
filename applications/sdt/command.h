
// Subset of enclavestate.h
// Only the Command specific parts that are helpful for formatting commands before encryption

#include "appPVRA.h"

#ifndef __COMMAND_H__
#define __COMMAND_H__


typedef struct {
    unsigned char data[32];
} secp256k1_prikey;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;



typedef uint32_t cType;

struct private_command {
	cType CT;
	struct cInputs CI;
	int seqNo;
};

struct clientCommand
{
	secp256k1_pubkey user_pubkey;
	struct private_command eCMD;
};




#endif
