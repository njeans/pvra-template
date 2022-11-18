//#include <stdio.h>
//#include <stdlib.h>

#include "merkletree.h"
#include "keccak256.h"
#include "util.h"


void hash_node(uint8_t* out, uint8_t *left, uint8_t *right, size_t size) {
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  keccak_update(&ctx_sha3, left, size);
//  print_hexstring_n(left, size);
  keccak_update(&ctx_sha3, right, size);
//  print_hexstring_n(right, size);
  keccak_final(&ctx_sha3, out);
//  printf(" -> ");
//  print_hexstring(out, 32);
}

void hash_leaf(uint8_t* out, uint8_t *leaf, size_t size) {
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  keccak_update(&ctx_sha3, leaf, size);
  keccak_final(&ctx_sha3, out);
}

uint32_t next_root_2(uint32_t num) {
    int v = num;
    v -= 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v += 1;
    return v;
}

int build_tree(merkle_tree *mt, uint8_t *leaves[], uint32_t num_leaves, uint32_t block_size) {
    uint32_t total_leaves = next_root_2(num_leaves);
    mt->num_leaves = total_leaves;
    mt->block_size = block_size;
    mt->num_nodes = 2*total_leaves - 1;
//    printf("num_nodes %d total_leaves %d\n",mt->num_nodes, total_leaves);
    mt->nodes = (uint8_t **) malloc(sizeof(uint8_t*) * mt->num_nodes);
    mt->leaves = (uint8_t **) malloc(sizeof(uint8_t*) * total_leaves);
    for (int i=0; i < total_leaves ; i++) {
        if (i < num_leaves) mt->leaves[i] = leaves[i];
        else mt->leaves[i] = (uint8_t *) malloc(block_size);
        mt->nodes[i] = (uint8_t *) malloc(HASH_SIZE);
        hash_leaf(mt->nodes[i], mt->leaves[i], mt->block_size);
//        printf("hashing leaf %d ", i);
//        print_hexstring_n(mt->leaves[i], block_size);
//        printf(" -> ");
//        print_hexstring(mt->nodes[i], HASH_SIZE);
    }
    int index = total_leaves;
    for (int j = 0; j < mt->num_nodes-1; j+=2) {
        uint8_t * l = mt->nodes[j];
        uint8_t * r = mt->nodes[j+1];
        mt->nodes[index] = (uint8_t *) malloc(HASH_SIZE);
//        printf("hashing %d+%d for index %d: ", j,j+1,index);
        hash_node(mt->nodes[index], l, r, HASH_SIZE);
        index++;
    }
    return 0;
}

void cleanup_tree(merkle_tree *mt) {
    if (!mt)
        return;
    if (mt->nodes) {
        for (int i=0; i<mt->num_nodes; i++){
            if(mt->nodes[i]) {
                free(mt->nodes[i]);
                mt->nodes[i] = NULL;
            }
        }
        free(mt->nodes);
        mt->nodes = NULL;

    }

    if (mt->leaves) {
        for (int i=0; i<mt->num_leaves; i++){
            if(mt->leaves[i]) {
                free(mt->leaves[i]);
                mt->leaves[i] = NULL;
            }
        }
       free(mt->leaves);
       mt->leaves = NULL;
    }

    return;
}

size_t calc_tree_size(uint32_t num_leaves, uint32_t block_size) {
    uint32_t total_leaves = next_root_2(num_leaves);
    uint32_t num_nodes = 2*total_leaves - 1;
    size_t ts = sizeof(block_size) + sizeof(num_leaves) + (total_leaves * block_size) + (num_nodes * HASH_SIZE);
    return ts;
}

//void memcpy_big_uint32(uint8_t* buff, uint32_t num) {
//    int x = 1;
//    char *p = (char *)&x;
//    uint32_t swapped;
//	if (p[0] == 1){
//        swapped = ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) | ((num<<24)&0xff000000);
//    } else {
//        swapped = num;
//    }
//   memcpy(buff, &swapped, 4);
//}

int serialize_tree(uint8_t * out, merkle_tree *mt) {
     int offset = 0;

     memcpy_big_uint32(out, mt->block_size);
//     printf("serialize block size %u; ", mt->block_size);
//     print_hexstring(out, sizeof(mt->block_size));
     offset+= sizeof(mt->block_size);

     memcpy_big_uint32(out + offset, mt->num_leaves);
     offset+= sizeof(mt->num_leaves);

     for(int i = 0; i < mt->num_leaves; i++) {
       memcpy(out + offset, mt->leaves[i], mt->block_size);
       offset += mt->block_size;
     }

     for(int i = 0; i < mt->num_nodes; i++) {
       memcpy(out + offset, mt->nodes[i], HASH_SIZE);
       offset += HASH_SIZE;
     }
     return offset;
}


//void print_hexstring_n(const void *vsrc, size_t len) {
//  const unsigned char *sp = (const unsigned char *)vsrc;
//  size_t i;
//  for (i = 0; i < len; ++i) {
//    printf("%02x", sp[i]);
//  }
//}

void print_tree(merkle_tree *mt) {
    int i;
    printf("leaves: %d [ ", mt->num_leaves);
    for(i=0; i<mt->num_leaves; i++){
        printf("\"");
        print_hexstring_n(mt->leaves[i], mt->block_size);
        if (i == mt->num_leaves-1)
            printf("\"]\n");
        else
            printf("\", ");
    }
    printf("nodes: %d [ ", mt->num_nodes);
    for(i=0; i<mt->num_nodes; i++){
        printf("\"");
        print_hexstring_n(mt->nodes[i], HASH_SIZE);
        if (i == mt->num_nodes-1)
            printf("\"]\n");
        else
            printf("\", ");
    }
    return;
}

//int main()
//{
//    size_t block_size = 8;
//    int num_leaves = 4;
//    char *data[num_leaves];
//    merkle_tree mt = {block_size, 0, num_leaves, NULL, NULL};
//    for (int i=0; i<num_leaves; i++) {
//        data[i] = (char *)malloc(sizeof(char) * block_size);
//        char buffer[block_size];
//        for (int j=0;j<block_size;j++) {
//            buffer[j] = i+1;
//        }
//        memcpy(data[i], buffer, block_size);
//    }
//    int res = build_tree(&mt, data, num_leaves, block_size);
//    print_tree(&mt);
//    char * buff = malloc(tree_size(&mt));
//    size_t s = serialize_tree(buff, &mt);
//    printf("\n");
//    print_hexstring_n(buff, s);
//    printf("\n");
//    cleanup_tree(&mt);
//}