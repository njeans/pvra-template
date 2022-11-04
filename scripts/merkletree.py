from web3 import Web3


def print_tree(nodes, leaves, index=-1, level=0, str_leaf=str, str_node=str):
    len_nodes = len(nodes) - 1
    if index == -1:
        index = len_nodes
    output = ""
    node = nodes[index]
    right_index = len_nodes-(2**(level+1)-1 + 2*((len_nodes-index) - 2**level + 1))
    left_index = right_index - 1
    if left_index >= 0:
        output += print_tree(nodes, leaves, left_index, level+1, str_leaf=str_leaf, str_node=str_node)
        output += str("\t\t" * level) + '-> (' + str_node(node) + ")" + "\n"
        output += print_tree(nodes, leaves, right_index, level+1, str_leaf=str_leaf, str_node=str_node)
    else:
        output += str("\t\t" * level) + '-> (' + str_node(node) + '):{' + str_leaf(leaves[index]) + "}" + "\n"
    return output


def check_tree(nodes, leaves, index=-1, level=0):
    len_nodes = len(nodes) -1
    if index == -1:
        index = len_nodes
    node = nodes[index]
    right_index = len_nodes-(2**(level+1)-1 + 2*((len_nodes-index) - 2**level + 1))
    left_index = right_index - 1
    if left_index < 0:
        return
    if index < len(leaves):
        assert node == bytes(Web3.keccak(leaves[index]))

    h = bytes(Web3.keccak(nodes[left_index] + nodes[right_index]))
    # print(index, ":", left_index, "+", right_index, (nodes[left_index] + nodes[right_index]).hex(), h.hex(),  node.hex())
    assert node == h
    check_tree(nodes, leaves, right_index, level+1)
    check_tree(nodes, leaves, left_index, level+1)


def build_tree(data):
    nl = len(data)
    num = 2**(nl-1) -1
    mt = [None for _ in range(num)]
    for i in range(nl):
        mt[i] = data[i]
    idx = nl
    for j in range(0, num-1, 2):
        l = mt[j]
        r = mt[j+1]
        h = l+r#Web3.keccak(l+r)
        mt[idx] = h#bytes(h))
        idx+=1
    print(mt)
    return mt


def parse_tree(data_raw):
    len_unit = 32
    # print("data_raw[:4]", data_raw[:4].hex())
    block_size = int.from_bytes(data_raw[:4], "big")
    num_leaves = int.from_bytes(data_raw[4:8], "big")
    num_nodes=2**(num_leaves-1) -1
    # print("block_size", block_size, "num_leaves", num_leaves, "num_nodes", num_nodes)
    leaves = []
    nodes = []
    end = 0
    for i in range(num_leaves):
        start = 8+(block_size*i)
        end = start + block_size
        leaves.append(data_raw[start:end])
    for i in range(num_nodes):
        start = 8 + (block_size*num_leaves) + (i*len_unit)
        end = start + len_unit
        nodes.append(data_raw[start:end])
    return nodes, leaves, end


if __name__ == '__main__':
    data_raw="000000010000000400000000000000000000000000000000000000000000000000000000010000000000000000000000000000000200000000000000000000000000000003000000f490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4608d81434d34af67be47cfee67e1b49b7dab9e35ef4f9def3f5ec3873939f5510eb8f89fe3b990c897127357905a499a4746f87facef2605ff288ae502afa77c34151af5bf6d8555688019a5c9a6049a934d700ec3d7a3b101686b3e2a26581facd6f4ef922fb5b78cd2f7ed26f6ec21793fc08e6aa8812d3a77a549e9141e9020b02eea2a0c9079939ccd0a9ab7c98db78cf905d0869668d9c4bb487d08b2504dbab6e9de058dd982da5f7ced653e1ae30b94a21ac8a5ba1b0d70f2211a052a00000000000000000000000000000000ffcf8fdee72ac11b5c542428b35eef5769c409f097e83885ef4e676481bfa85f099bd4bd3a30f1c769810bcfc0a84929e0a40eac"
    nodes, leaves, _ = parse_tree(bytes.fromhex(data_raw))
    print([x.hex() for x in leaves])
    print([x.hex() for x in nodes])
    print(print_tree(nodes))
    check_tree(nodes, leaves)
    # x=build_tree([b'11',b'22',b'33',b'44'])
    # x=[ "0101010101010101", "0202020202020202", "0303030303030303", "0404040404040404", "e32ff9982eb4ccbbab8d4b38ef6c7344270c9fa58a90d8b6285a938bb8f0c438", "4879d8c259aa9355056e331abc6e230bd2e53d0cf9a9f5e306b599a6ec2c9f8e", "ef0345d61556f2e5bdde2bf2e4d5d881a120d285467e59ebc5058fe2e5ba3bc1"]
    # x.reverse()
    # print(print_tree_str(x))
    # b=[bytes.fromhex(y) for y in x]
    # b=x
    # check_tree(b)
    # print(print_tree(b))
    # x=build_tree_tmp([b'1',b'2',b'3',b'4'])
    # x.reverse()
    # print(print_tree_tmp(x))
    # check_tree_tmp(x)
    # print(print_tree([10, 11, 12], 0))
    # print(print_tree([10, 11, 12, 13, 14, 15, 16], 0))
    # print(print_tree([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24], 0))
