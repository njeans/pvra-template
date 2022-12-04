//#include <stdlib.h>
#include <enclave_t.h>

typedef struct {
    uint32_t leaf_size;
    size_t num_nodes;
    uint32_t num_leaves;
    uint8_t **nodes;
    uint8_t **leaves;
} merkle_tree;

int build_tree(merkle_tree *mt, uint8_t **leaves, uint32_t num_leaves, uint32_t leaf_size) ;
void print_tree(merkle_tree *mt);
size_t calc_tree_size(uint32_t num_leaves, uint32_t leaf_size);
int serialize_tree(uint8_t * out, merkle_tree *mt);
void cleanup_tree(merkle_tree *mt);