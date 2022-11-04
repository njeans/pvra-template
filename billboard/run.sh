set -e
export ENCLAVE_PUBLIC_KEY=$(cat test_data/enclave_pk)
export ENCLAVE_PUBLIC_KEY_SIG=$(cat test_data/enclave_pk_sig)
echo "$ENCLAVE_PUBLIC_KEY $ENCLAVE_PUBLIC_KEY"
echo "ENCLAVE_PUBLIC_KEY_SIG $ENCLAVE_PUBLIC_KEY_SIG"
export CONTRACT_ADDRESS=$(cat ca)
#python billboard.py user_verify_info 1
#python billboard.py user_verify_info 2
#python billboard.py user_verify_info 3
#python billboard.py user_verify_info 4
#
#
python billboard.py user_add_data_bb 1 $(cat test_data/user_1_data)
python billboard.py user_add_data_bb 3 $(cat test_data/user_3_data)
python billboard.py user_add_data_bb 4 $(cat test_data/user_4_data)

#python billboard.py admin_ user_addr user_addr_sig