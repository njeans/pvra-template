// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.4.22 <0.9.0;

contract Billboard {
    struct User {
        mapping (uint => bytes) user_data;//mapping data from every audit num won't necessarily be provided
        uint last_audit_num;
        mapping (uint => bool) added_data;//mapping data from every audit num won't necessarily be provided
        mapping (uint => bool) called_audit_timeout;//mapping data from every audit num won't necessarily be provided
     }

    struct AuditData {
//        bytes merkle_root;
        address[] included_user_addresses;
        bytes32[] included_data_hashes;
    }

    struct UserData {
        address user_address;
        uint last_audit_num;
        bytes data;
    }

    address admin_addr;

    mapping (address => User) user_info;
    address[] public user_list;

    mapping (uint => AuditData) audit_data;

    uint public contract_balance;
    uint message_omission_cost;
    uint audit_delay_cost;
    uint public max_penalty;

    uint public last_audit_num;
    uint last_audit_block_num;
    uint audit_time_limit = 10;

    bool public initialized; //require that can only initialize once
    bool omission_detected;
    bool timeout_detected;

    address public enclave_address;
    bytes public enclave_publickey;
    bytes public enclave_publickey_sig;

    bytes32 public tmp_hash;
    bytes public tmp_byte;
    bytes public tmp_byte2;
    address public tmp_addr;

    constructor(bytes memory enclave_key, bytes memory signature) {
        admin_addr = msg.sender;
        enclave_publickey = enclave_key;
        enclave_address = address(uint160(uint256(keccak256(enclave_key))));
        initialized = false;
        enclave_publickey_sig = signature;
    }

    function fund() public payable {
        require(msg.sender == admin_addr); //good bugs..bugs that benefit you e.g. someone else funding my contract
        contract_balance+=msg.value;
    }

    function init_user_db(address[] memory user_addresses, bytes memory signature) public {
        require(msg.sender == admin_addr);
        require(initialized == false);

        bytes32 users_hash = hash_address_list(user_addresses);
        address signer = recover(users_hash, signature);
	    tmp_addr = signer;
        require(signer == enclave_address);
        uint num_users = user_addresses.length;
        audit_delay_cost = 1;
        message_omission_cost = audit_delay_cost * num_users;
        max_penalty = (message_omission_cost + audit_delay_cost) *  num_users;
        last_audit_block_num = block.number;
        initialized = true;
        last_audit_num = 0;
        user_list = user_addresses;
        omission_detected=false;
        timeout_detected=false;
    }

    function add_user_data(bytes memory encrypted_command_and_data, uint audit_num) public {
        require(initialized);
        require(last_audit_num+1 == audit_num);
        User storage user = user_info[msg.sender];
        require(user.last_audit_num < audit_num);
        user.last_audit_num = audit_num;
        user.user_data[audit_num] = encrypted_command_and_data;
        user.added_data[audit_num] = true;
    }

    function admin_audit(uint audit_num, address[] memory included_user_addresses,
        bytes32[] memory included_data_hashes, bytes memory audit_log_signature) public {
        require(msg.sender == admin_addr);
        require(initialized);
        require(last_audit_num < audit_num);
        last_audit_num = audit_num;
        last_audit_block_num = block.number;
        bytes32 audit_log_hash = hash_audit_data(audit_num, included_user_addresses, included_data_hashes);
        address signer = recover(audit_log_hash, audit_log_signature);
        require(signer == enclave_address);
        audit_data[audit_num] = AuditData(included_user_addresses, included_data_hashes);
    }

    function detect_omission(address user_addr, uint audit_num) public {
        require(initialized);
        require(last_audit_num >= audit_num);
        User storage user = user_info[user_addr];
        AuditData memory audit_log = audit_data[audit_num];
        require(user.added_data[audit_num] == true);
        int index = find_address(audit_log.included_user_addresses, user_addr);
        if (index == -1) {
            omission_detected = true;
        } else {
            if (keccak256(user.user_data[audit_num]) != audit_log.included_data_hashes[uint(index)]) {
                omission_detected = true;
            }
        }
    }

    function detect_timeout(address user_addr) public {
        User storage user = user_info[user_addr];
        if ((last_audit_block_num + audit_time_limit) < block.number) {
            timeout_detected = true;
        }
    }

    function get_user(address user_addr, uint audit_num) public view returns (UserData memory) {
        User storage user = user_info[user_addr];
        return UserData(user_addr, user.last_audit_num, user.user_data[audit_num]);
    }

    function get_all_users() public view returns (address[] memory) {
        return user_list;
    }

    function get_all_user_data(uint audit_num) public view returns (UserData[] memory) {
        UserData[] memory user_datas = new UserData[](user_list.length);
        uint user_count = 0;

        for (uint i = 0; i < user_list.length; i++) {
            address addr = user_list[i];
            User storage user = user_info[addr];
            if (user.user_data[audit_num].length  != 0) {
                UserData memory user_data = UserData(addr, user.last_audit_num, user.user_data[audit_num]);
                user_datas[user_count] = user_data;
                user_count++;
            }
        }
        return user_datas;
    }

    function get_enclave_publickey() public view returns (bytes memory, bytes memory) {
        return (enclave_publickey, enclave_publickey_sig);
    }

    function hash_address_list(
        address[] memory _addresses) public returns (bytes32) {
        uint len = _addresses.length;
        bytes memory packed = abi.encodePacked(_addresses);
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        packed = abi.encodePacked(eth_prefix,uint2str(packed.length),packed);
        tmp_byte=packed;
        bytes32 hash = keccak256(packed);
        tmp_hash=hash;
        return hash;
    }

    function hash_audit_data(uint audit_num, address[] memory _addresses, bytes32[] memory _data) public returns (bytes32) {
        require(_addresses.length == _data.length);
        uint len = _addresses.length;
        bytes memory eth_prefix = '\x19Ethereum Signed Message:\n';
        bytes memory packed = abi.encodePacked(uint2str(audit_num), _addresses, _data);
//        for (uint i = 0; i < len; i++) {
//            packed = abi.encodePacked(packed, toBytes(_addresses[i]), _data[i]);
//        }
        packed = abi.encodePacked(eth_prefix,packed.length,packed);

        tmp_byte2=abi.encodePacked(packed.length);
        bytes32 hash = keccak256(packed);
        tmp_hash=hash;
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

    function address2string(address addr) public pure returns(string memory) {
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

function toBytes(address a) public pure returns (bytes memory b){
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


    function bytes2Address(bytes memory bys) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 32))
        }
    }
}

