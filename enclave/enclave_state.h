//#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
//
//#include <mbedtls/entropy.h>
//#include <mbedtls/ctr_drbg.h>
//#include <mbedtls/bignum.h>
//#include <mbedtls/pk.h>
//#include <mbedtls/rsa.h>
#include <enclave_t.h>
#include <secp256k1.h>

#include "constants.h"
#include "appPVRA.h"
#ifdef MERKLE_TREE
#include "merkletree.h"
#endif

#ifndef ENCLAVESTATE_H
#define ENCLAVESTATE_H


struct EK
{
  	//uint8_t priv_key_buffer[2049];
  	//uint8_t pub_key_buffer[2049];
	//sgx_ec256_private_t sign_prikey;
	//sgx_ec256_public_t sign_pubkey;


	secp256k1_pubkey sig_pubkey;
	secp256k1_prikey sig_prikey;
	secp256k1_pubkey enc_pubkey;
	secp256k1_prikey enc_prikey;
};



typedef struct _sha256_hash_t
{
    uint8_t bytes[32];
} sha256_hash_t;


struct AL
{
	packed_address_t user_addresses[MAX_LOG_SIZE];
	sha256_hash_t command_hashes[MAX_LOG_SIZE];
	uint64_t seqNo[MAX_LOG_SIZE];
};



struct AUD
{
	uint64_t num_pubkeys;
	uint8_t master_user_pubkeys[MAX_USERS][64];
	
	struct AL auditlog;
	uint64_t audit_index;
	uint64_t audit_num;
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
	uint64_t seqno[MAX_USERS];
};


struct ES
{
	struct EK enclavekeys;
	struct SCS counter;
	struct AR antireplay;
	struct AD appdata;
	struct AUD auditmetadata;
}; 

typedef uint32_t cType;

struct private_command {
	cType CT;
	struct cInputs CI;
};


struct clientCommand
{
	uint64_t seqNo;
	uint8_t user_pubkey[64];
	struct private_command eCMD;
};

struct dynamicDS
{
	uint8_t * buffer;
	size_t buffer_size;
};

struct dAppData
{
	struct dynamicDS **dDS;
	int num_dDS;
};


sgx_status_t unseal_enclave_state(const sgx_sealed_data_t *, struct ES *, struct dAppData *);
sgx_status_t seal_enclave_state(const sgx_sealed_data_t *, size_t, size_t *, struct ES *, struct dAppData *);

#ifdef MERKLE_TREE
size_t calc_auditlog_buffer_size(struct ES * enclave_state, merkle_tree * mt, size_t * out_mt_size);
#else
size_t calc_auditlog_buffer_size(struct ES * enclave_state);
#endif
sgx_status_t ecall_calc_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size, size_t *newauditlog_buffer_size);

#endif
