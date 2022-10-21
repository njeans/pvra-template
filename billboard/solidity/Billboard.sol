// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Billboard {
    struct User {
        mapping (uint => bytes) user_data;
        uint last_audit_num;
        mapping (uint => bool) called_add_data;//data from every audit num won't necessarily be provided
    }

    struct AuditData {
        bytes32 merkle_root;
        address[] included_user_ids;
        bytes32[] included_data_hashes;
    }

    struct UserData {
        address user_address;
        uint last_audit_num;
        bytes data;
    }

    mapping (address => User) user_info;
    address[] public user_list;

    mapping (uint => AuditData) audit_data;

    uint32 public last_audit_num;
    uint last_audit_block_num;
    uint audit_time = 10;
    uint post_time = 5;

    bool public initialized; //require that can only initialize once
    bool public omission_detected;
    bool public timeout_detected;

    address public admin_addr;
    address public enclave_address;
    bytes public enclave_sign_key;
    bytes public ias_report;

    bytes32 public tmp_hash;
    bytes public tmp_byte;
    bytes32 public tmp_hash2;
    address public tmp_addr;
    uint public tmp_idx;

    constructor(bytes memory enclave_sign_key_, bytes memory ias_report_) {
        require(enclave_sign_key_.length == 64);
        admin_addr = msg.sender;
        enclave_sign_key = enclave_sign_key_;
        enclave_address = address(uint160(uint256(keccak256(enclave_sign_key_))));
        initialized = false;
        ias_report = ias_report_;
    }

    function initialize(address[] memory user_addresses, bytes memory signature) public {

        require(msg.sender == admin_addr);
        bytes32 users_hash = hash_address_list(user_addresses);
        address signer = recover(users_hash, signature);
        require(signer == enclave_address);
        tmp_addr = signer;
        tmp_hash = users_hash;
        last_audit_block_num = block.number;//starts timer for next audit
        initialized = true;
        last_audit_num = 0;
        user_list = user_addresses;
        omission_detected=false;
        timeout_detected=false;
    }

    function add_user_data(bytes memory encrypted_command_and_data) public {
        require(initialized);
        User storage user = user_info[msg.sender];
        uint32 audit_num = last_audit_num+1;
        require(user.called_add_data[audit_num] == false);
        user.last_audit_num = audit_num;
        //users can only add 1 set
        //of data per audit time period
        user.user_data[audit_num] = encrypted_command_and_data;
        user.called_add_data[audit_num] = true;
    }

    function audit_start() public {
        require(msg.sender == admin_addr);
        require(initialized);
        require(last_audit_block_num + audit_time >= block.number);
        last_audit_num++;
    }

    function audit_end(bytes memory audit_log_signature,
        address[] memory included_user_ids,
        bytes32[] memory included_data_hashes) public {
        require(msg.sender == admin_addr);
        require(initialized);
        // last_audit_num was incremented in audit_start()
        last_audit_block_num = block.number;
        bytes32 audit_log_hash = hash_audit_data(last_audit_num, included_user_ids, included_data_hashes);
        address signer = recover(audit_log_hash, audit_log_signature);
//        tmp_addr = signer;
//        tmp_hash = audit_log_hash;
        require(enclave_address == signer);
        audit_data[last_audit_num] = AuditData("", included_user_ids, included_data_hashes);
    }

    function audit_end_merkle(bytes memory audit_log_signature,
        address[] memory included_user_ids, bytes32[] memory included_data_hashes,
         bytes[] calldata leaves, bytes32[] calldata proof) public {
        require(msg.sender == admin_addr);
        require(initialized);
        // last_audit_num was incremented in audit_start()
        last_audit_block_num = block.number;
        bytes32 audit_log_hash = hash_audit_data_merkle(leaves, proof, last_audit_num, included_user_ids, included_data_hashes);
        address signer = recover(audit_log_hash, audit_log_signature);
        require(enclave_address == signer);
        check_proof(proof, leaves);
        audit_data[last_audit_num].merkle_root = proof[proof.length-1];
    }

    function prove_omission_data(address user_id, uint32 audit_num) public {
        require(initialized);
        require(last_audit_num >= audit_num);
        User storage user = user_info[user_id];
        require(user.called_add_data[audit_num] == true);
        AuditData memory audit_log = audit_data[audit_num];

        int index = find_address(audit_log.included_user_ids, user_id);
//        tmp_idx = index;
        if (index == -1 ) {
            omission_detected = true;
        } else {
            bytes32 user_data_hash = keccak256(user.user_data[audit_num]);
            if (audit_log.included_data_hashes[uint(index)] != user_data_hash) {
                omission_detected = true;
            }
        }
    }

    function prove_omission_sig(address user_id, uint32 audit_num, bytes32 data_hash, bytes memory confirm_signature) public {
        require(initialized);
        require(last_audit_num >= audit_num);
        bytes32 confirm_hash = hash_confirmation(user_id, audit_num, data_hash);
        address signer = recover(confirm_hash, confirm_signature);
        require(admin_addr == signer);
//        tmp_addr = signer;
        AuditData memory audit_log = audit_data[audit_num];
        int index = find_address(audit_log.included_user_ids, user_id);
        if (index == -1 ) {
            omission_detected = true;
        }
    }

    function detect_timeout() public {
        if ((last_audit_block_num + audit_time + post_time) < block.number) {
            timeout_detected = true;
        }
    }

    function hash_address_list(address[] memory _addresses) internal pure returns (bytes32) {
        bytes memory packed = abi.encodePacked(_addresses);
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix,uint2str(packed.length),packed);
        bytes32 hash = keccak256(packed);
        return hash;
    }

    //todo change packing audit_num?
    //todo pure
    function hash_audit_data(uint32 audit_num, address[] memory _addresses, bytes32[] memory _data) internal pure returns (bytes32) {
        require(_addresses.length == _data.length);
        bytes memory packed = abi.encodePacked(audit_num, _addresses, _data);
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix, uint2str(packed.length), packed);
//        tmp_byte = packed;
        bytes32 hash = keccak256(packed);
        return hash;
    }


    function hash_audit_data_merkle(bytes[] calldata leaves, bytes32[] calldata proof,
        uint32 audit_num, address[] memory _addresses, bytes32[] memory _data) public pure returns (bytes32) {
        require(_addresses.length == _data.length);
        bytes memory packed = abi.encodePacked(uint32(leaves[0].length), uint32(leaves.length));
        for (uint i = 0; i < leaves.length; i++){
            packed = abi.encodePacked(packed, leaves[i]);
        }
        packed = abi.encodePacked(packed, proof, audit_num, _addresses, _data);
//        tmp_byte = packed;
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix, uint2str(packed.length), packed);
        bytes32 hash = keccak256(packed);
        return hash;
    }
    function hash_confirmation(address _addresses, uint32 audit_num, bytes32 data_hash) internal pure returns (bytes32) {
        bytes memory packed = abi.encodePacked(uint2str(audit_num), _addresses, data_hash);
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix, uint2str(packed.length), packed);
        bytes32 hash = keccak256(packed);
        return hash;
    }

   function hash_root(bytes32 root) internal pure returns(bytes32) {
//        bytes memory packed = abi.encodePacked(uint2str(audit_num), root);
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        bytes memory packed = abi.encodePacked(eth_prefix, "32", root);
        bytes32 hash = keccak256(packed);
        return hash;
    }

    function find_address(address[] memory list, address val) internal pure returns (int) {
        uint len = list.length;
        for (uint i = 0; i < len; i++) {
            if (list[i] == val) {
                return int(i);
            }
        }
        return -1;
    }

    function get_user(address user_addr, uint32 audit_num) public view returns (UserData memory) {
        User storage user = user_info[msg.sender];
        return UserData(user_addr, user.last_audit_num, user.user_data[audit_num]);
    }


    function get_all_user_data(uint32 audit_num) public view returns (UserData[] memory) {
        uint user_count = 0;
        for (uint i = 0; i < user_list.length; i++) {
            address addr = user_list[i];
            User storage user = user_info[addr];
            if (user.called_add_data[audit_num] == true) {
                user_count++;
            }
        }

        UserData[] memory user_data = new UserData[](user_count);
        uint index = 0;
        for (uint i = 0; i < user_list.length; i++) {
            address addr = user_list[i];
            User storage user = user_info[addr];
            if (user.called_add_data[audit_num] == true) {
                UserData memory user_datum = UserData(addr, user.last_audit_num, user.user_data[audit_num]);
                user_data[index] = user_datum;
                index++;
            }
        }
        return user_data;
    }

    function check_proof(bytes32[] calldata proof, bytes[] calldata leaves) internal pure {
        for (uint i = 0; i < leaves.length; i++) {
            require(proof[i] == keccak256(leaves[i]));
        }
        check_proof_(proof, int(proof.length)-1, 0);
    }

    function check_proof_(bytes32[] calldata proof, int index, uint level) internal pure {
        int right_index = int(proof.length) - 1 -(int(2**(level+1))-1 + 2*((int(proof.length)-1-index) - int(2**level) + 1));
        int left_index = right_index - 1;
        if (left_index < 0) {
            return;
        }
        bytes32 h = keccak256(abi.encodePacked(proof[uint(left_index)], proof[uint(right_index)]));
        require(h == proof[uint(index)]);
        check_proof_(proof, left_index, level+1);
        check_proof_(proof, right_index, level+1);
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
                revert("ECDSA: invalid signature 's' value");
            }
            address signer = ecrecover(hash, v, r, s);
            if (signer == address(0)) {
                revert("ECDSA: invalid signature");
            }
            return signer;
        } else {
            revert("ECDSA: invalid signature length");
        }
    }

    function address2string(address addr) internal pure returns(string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory data = abi.encodePacked(addr);
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint i = 0; i < data.length; i++) {
            str[2+i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[3+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    function toBytes(address a) internal pure returns (bytes memory b){
        assembly {
            let m := mload(0x40)
            a := and(a, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(add(m, 20), xor(0x140000000000000000000000000000000000000000, a))
            mstore(0x40, add(m, 52))
            b := m
        }
    }

    function uint2str( uint256 _i ) internal pure returns (string memory str) {
        if (_i == 0)
        {
            return "0";
        }
        uint256 j = _i;
        uint256 length;
        while (j != 0)
        {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        j = _i;
        while (j != 0)
        {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        str = string(bstr);
    }


    function bytes2Address(bytes memory bys) internal pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 32))
        }
    }


}