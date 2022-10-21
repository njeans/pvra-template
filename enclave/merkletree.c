#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "merkletree.h"
#include "keccak256.h"


void hash_node(char* out, char *left, char *right, size_t size) {
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  keccak_update(&ctx_sha3, left, size);
  keccak_update(&ctx_sha3, right, size);
  keccak_final(&ctx_sha3, out);
}

void hash_leaf(char* out, char *leaf, size_t size) {
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  keccak_update(&ctx_sha3, leaf, size);
  keccak_final(&ctx_sha3, out);
}

int build_tree(merkle_tree *mt, char *leaves[], uint32_t num_leaves, uint32_t block_size) {
    mt->num_leaves = num_leaves;
    mt->block_size = block_size;
    mt->num_nodes = (1 << (num_leaves-1)) - 1;
    mt->nodes = (char **) malloc(sizeof(char*) * mt->num_nodes);
    mt->leaves = (char **) malloc(sizeof(char*) * num_leaves);
    for (int i=0; i < num_leaves ; i++) {
        mt->leaves[i] = leaves[i];
        mt->nodes[i] = (char *) malloc(32);
        hash_leaf(mt->nodes[i], leaves[i], mt->block_size);
    }
    int index = num_leaves;
    for (int j = 0; j < mt->num_nodes-1; j+=2) {
        char * l = mt->nodes[j];
        char * r = mt->nodes[j+1];
        mt->nodes[index] = (char *) malloc(32);
        hash_node(mt->nodes[index], l, r, 32);
        index++;
    }
    return 0;
}

void cleanup_tree(merkle_tree *mt) {
    if (!mt)
        return;
    if (mt->nodes) {
        for (int i=0; i<mt->num_nodes; i++)
            if(mt->nodes[i])
                free(mt->nodes[i]);
       free(mt->nodes);
    }
    if (mt->leaves) {
        for (int i=0; i<mt->num_leaves; i++)
            if(mt->nodes[i])
                free(mt->leaves[i]);
       free(mt->leaves);
    }
    return;
}

size_t tree_size(merkle_tree * mt) {
    return sizeof(mt->block_size) + sizeof(mt->num_leaves) + (mt->num_leaves * mt->block_size) + (mt->num_nodes * 32);
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

int serialize_tree(char * out, merkle_tree *mt) {
     int offset = 0;
     int hash_size = 32;
     memcpy_big_uint32(out + offset, mt->block_size);
     offset+= sizeof(mt->block_size);
     memcpy_big_uint32(out + offset, mt->num_leaves);
     offset+= sizeof(mt->num_leaves);

     for(int i = 0; i < mt->num_leaves; i++) {
       memcpy(out + offset, mt->leaves[i], mt->block_size);
       offset += mt->block_size;
     }
     for(int i = 0; i < mt->num_nodes; i++) {
       memcpy(out + offset, mt->nodes[i], hash_size);
       offset += hash_size;
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
    printf("[ ");
    for(i=0; i<mt->num_leaves; i++){
        printf("\"");
        print_hexstring_n(mt->nodes[i], mt->block_size);
        printf("\", ");
    }
    for(i=0; i<mt->num_leaves; i++){
        printf("\"");
        print_hexstring_n(mt->nodes[i], 32);
        printf("\", ");
    }
    for(i=mt->num_leaves; i<mt->num_nodes; i++){
        printf("\"");
        print_hexstring_n(mt->nodes[i], 32);
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
//    printf("a\n");
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