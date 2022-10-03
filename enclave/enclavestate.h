#include <sgx_tcrypto.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "appPVRA.h"

#ifndef ENCLAVESTATE_H
#define ENCLAVESTATE_H

#define SHA256_HASHLEN

struct EK
{
  	uint8_t priv_key_buffer[2049];
  	uint8_t pub_key_buffer[2049];
	sgx_ec256_private_t sign_prikey;
	sgx_ec256_public_t sign_pubkey;

	uint8_t k1pubkey[64];
	uint8_t k1prikey[32];

};



typedef struct _sha256_hash_t
{
    uint8_t bytes[32];
} sha256_hash_t;


struct AL
{
	sgx_ec256_public_t user_pubkeys[10];
	sha256_hash_t command_hashes[10];
};



struct AUD
{
	sgx_ec256_public_t master_user_pubkeys[5];
	struct AL auditlog;
	int audit_offset;
	int audit_version_no;
};






struct SCS
{
	//sgx_ec256_public_t CCF_key;
	//const char CCF_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAs1l0PEtgQRtk5mkclhMFTtkLGWUG/11ZiMG+wA7FCIljrs0u6rzT\n8XSILc0Gr7JEAQO+2r8r23HQnqQMRrAL8TnTHXWrClat7SFoOQlIQ3Oy0C2sxmk+\nKFhKFZy9fxCVcy4H+Qu6OF4HY6Aym08/oPBhIEnw7W29eH7VrkCrRDa9MwYZibD1\nyz8GM7OwrltU5wWt8GL0SMcMRe0rAfziwS+8u+rGFGVrPZ8f2ZhZrq0bfCIWdtp6\n58K1LqKomLayIDowy+9Lk79nI17xV7YnJammzZgSaNQXy+Az9c1rszT7RHK4rhUN\n0J8IDxuZVpzWjIEJQXY92yZQ0x7loNq8uwIDAQAB\n-----END RSA PUBLIC KEY-----\n";
	uint8_t CCF_key[2049];
	char freshness_tag[32];

};


struct AR
{
	int seqno[10];
};


struct ES
{
	struct EK enclavekeys;
	struct SCS counter;
	struct AR antireplay;
	struct AD appdata;
	struct AUD auditmetadata;
}; 


struct cType 
{
	int tid;
};

struct clientCommand
{
	struct cType CT;
	struct cInputs CI;
	int seqNo;
	int cid;
};

struct dynamicDS
{
	uint8_t *buffer;
	size_t buffer_size;
};

struct dAppData
{
	struct dynamicDS **dDS;
	int num_dDS;
};



#endif
