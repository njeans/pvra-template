#include <secp256k1.h>
#include "enclavestate.h"


void get_address(secp256k1_pubkey * pubkey, address_t* out);

void get_packed_address(secp256k1_pubkey * pubkey, packed_address_t* out);

void hash_address_list(secp256k1_pubkey * pubkey_list, int num_pubkeys, char * hash_out_32);

void memcpy_big_uint32(uint8_t* buff, uint32_t val);