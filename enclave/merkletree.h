//#include <stdlib.h>
#include <enclave_t.h>

typedef struct {
    uint32_t block_size;
    size_t num_nodes;
    uint32_t num_leaves;
    char **nodes;
    char **leaves;
} merkle_tree;

int build_tree(merkle_tree *mt, char *leaves[], uint32_t num_leaves, uint32_t block_size) ;
void print_tree(merkle_tree *mt);
size_t tree_size(merkle_tree * mt);
int serialize_tree(char * out, merkle_tree *mt);
void cleanup_tree(merkle_tree *mt);