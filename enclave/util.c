#include <secp256k1.h>
#include "keccak256.h"
#include "enclavestate.h"


void get_address(secp256k1_pubkey * pubkey, address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[32];
    keccak_final(&ctx, result);
    memcpy(out, &result[12], sizeof(address_t));
}

void get_packed_address(secp256k1_pubkey * pubkey, packed_address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[32];
    keccak_final(&ctx, result);
    memset(out, 0, sizeof(packed_address_t));
    memcpy((char *)out + 12, &result[12], sizeof(address_t));
//    printf("get_packed_address_result=");
//    print_hexstring(result, sizeof(result));
}

//solidity abi.packed([]address) function left pads address to 32 bytes
void hash_address_list(secp256k1_pubkey * pubkey_list, int num_pubkeys, char * hash_out_32) {
  packed_address_t * addr_buff = (packed_address_t *) calloc(num_pubkeys, sizeof(packed_address_t));//todo check null
  for (int i = 0; i < num_pubkeys; i++) {
    get_packed_address(&pubkey_list[i], &addr_buff[i]);
  }
  char eth_prefix[100];
  int s = sprintf(eth_prefix,"%cEthereum Signed Message:\n%d", 25, sizeof(packed_address_t) * num_pubkeys);
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  //s-1 don't want '{0}' string deliminator
  keccak_update(&ctx_sha3, eth_prefix, s-1);
  keccak_update(&ctx_sha3, addr_buff, sizeof(packed_address_t)*num_pubkeys );
  keccak_final(&ctx_sha3, hash_out_32);
  free(addr_buff);
}

void memcpy_big_uint32(uint8_t* buff, uint32_t num) {
    int x = 1;
    char *p = (char *)&x;
    uint32_t swapped;
	if (p[0] == 1){
        swapped = __builtin_bswap32(num);
    } else {
        swapped = num;
    }
   memcpy(buff, &swapped, 4);
}


void memcpy_big_uint64(uint8_t* buff, uint64_t num) {
    int x = 1;
    char *p = (char *)&x;
    uint64_t swapped;
	if (p[0] == 1){
        swapped = __builtin_bswap64(num);
    } else {
        swapped = num;
    }
   memcpy(buff, &swapped, 8);
}
/*
void save_seal() {
  size_t new_unsealed_data_size = sizeof(enclave_state) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    new_unsealed_data_size += sizeof(struct dynamicDS);
    new_unsealed_data_size += dAD.dDS[i]->buffer_size;
  }


  uint8_t *const new_unsealed_data = (uint8_t *)malloc(new_unsealed_data_size);
  printf("e %p %d %zu %u %u %p %d\n",new_unsealed_data, new_unsealed_data_size,new_unsealed_data_size, sizeof(enclave_state) , sizeof(struct dAppData), &enclave_state, sizeof(struct ES));

  if (new_unsealed_data == NULL) {
      printf("[ecPVRA] malloc new_unsealed_data blob error.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
  }

  int new_unsealed_offset = 0;

  memcpy(new_unsealed_data + new_unsealed_offset, &enclave_state, sizeof(struct ES));
  new_unsealed_offset += sizeof(struct ES);
  printf("d\n");

  memcpy(new_unsealed_data + new_unsealed_offset, &dAD, sizeof(struct dAppData));
  new_unsealed_offset += sizeof(struct dAppData);
  printf("c\n");

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i], sizeof(struct dynamicDS));
    new_unsealed_offset += sizeof(struct dynamicDS);
  }
  printf("b\n");

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i]->buffer, dAD.dDS[i]->buffer_size);
    new_unsealed_offset += dAD.dDS[i]->buffer_size;
  }

  if(new_unsealed_offset != new_unsealed_data_size) {
    printf("[ecPVRA] creating new_unsealed_data blob error.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // FREE metadata structs
  for(int i = 0; i < dAD.num_dDS; i++) {
    if(dAD.dDS[i] != NULL)
      free(dAD.dDS[i]);
  }

  if(dAD.dDS != NULL)
    free(dAD.dDS);
  uint32_t seal_size = sgx_calc_sealed_data_size(0U, new_unsealed_data_size);
  if(A_DEBUGRDTSC) printf("[ecPVRA] New seal_size: [%d]\n", seal_size);

  //printf("[ecPVRA] sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  //if(sealedout_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
  ret = sgx_seal_data(0U, NULL, new_unsealed_data_size, new_unsealed_data, seal_size, (sgx_sealed_data_t *)newsealedstate);
  if(ret !=SGX_SUCCESS) {
    print("[ecPVRA] sgx_seal_data() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //}
  //else {
  //  printf("[ecPVRA] Size allocated is less than the required size!\n");
  //  ret = SGX_ERROR_INVALID_PARAMETER;
  //  goto cleanup;
  //}

  if(A_DEBUGPRINT) printf("[ecPVRA] Enclave State sealed success\n");
  ret = SGX_SUCCESS;

}*/
