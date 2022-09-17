#include <sgx_tcrypto.h>

#ifndef ENCLAVESTATE_H
#define ENCLAVESTATE_H

struct EK
{
	sgx_ec256_private_t encrypt_prikey;
	sgx_ec256_public_t encrypt_pubkey;
	sgx_ec256_private_t sign_prikey;
	sgx_ec256_public_t sign_pubkey;

};

struct SCS
{
	sgx_ec256_public_t CCF_key;
	//const char CCF_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAs1l0PEtgQRtk5mkclhMFTtkLGWUG/11ZiMG+wA7FCIljrs0u6rzT\n8XSILc0Gr7JEAQO+2r8r23HQnqQMRrAL8TnTHXWrClat7SFoOQlIQ3Oy0C2sxmk+\nKFhKFZy9fxCVcy4H+Qu6OF4HY6Aym08/oPBhIEnw7W29eH7VrkCrRDa9MwYZibD1\nyz8GM7OwrltU5wWt8GL0SMcMRe0rAfziwS+8u+rGFGVrPZ8f2ZhZrq0bfCIWdtp6\n58K1LqKomLayIDowy+9Lk79nI17xV7YnJammzZgSaNQXy+Az9c1rszT7RHK4rhUN\n0J8IDxuZVpzWjIEJQXY92yZQ0x7loNq8uwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

	char freshness_tag[64];

};


struct AR
{
	int seqno[10];
};

struct AD
{
	int i;
};



struct ES
{
	struct EK enclavekeys;
	struct SCS counter;
	struct AR antireplay;
	struct AD appdata;
}; 



#endif
