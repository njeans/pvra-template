#include <enclave_t.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "constants.h"


void get_address(secp256k1_pubkey * pubkey, address_t* out);

void get_packed_address(secp256k1_pubkey * pubkey, packed_address_t* out);

void hash_address_list(secp256k1_pubkey * pubkey_list, int num_pubkeys, uint8_t * hash_out_32);

void keccak256(uint8_t *buff, size_t buff_size, uint8_t * hash_out_32);

void memcpy_big_uint32(uint8_t* buff, uint32_t val);

void hexstr_to_bytes(char * hexstr, size_t len, uint8_t * bytes);

sgx_status_t genkey_secp256k1(unsigned char seed, secp256k1_prikey * out_seckey, secp256k1_pubkey *out_pubkey, unsigned char *out_pubkey_ser);

sgx_status_t sign_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_signature *out_sig, unsigned char *sig_ser);

sgx_status_t sign_rec_secp256k1(secp256k1_prikey seckey, unsigned char data_hash[HASH_SIZE], secp256k1_ecdsa_recoverable_signature *out_sig, unsigned char *sig_ser);

sgx_status_t genkey_aesgcm128(uint8_t other_pubkey[64], uint8_t my_privkey[32], unsigned char AESkey[AESGCM_128_KEY_SIZE]);