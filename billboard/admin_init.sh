set -e
#export ENCLAVE_PUBLIC_KEY=$(cat test_data/enclave_pk)
#export ENCLAVE_PUBLIC_KEY_SIG=$(cat test_data/enclave_pk_sig)
#echo "$ENCLAVE_PUBLIC_KEY $ENCLAVE_PUBLIC_KEY"
#echo "ENCLAVE_PUBLIC_KEY_SIG $ENCLAVE_PUBLIC_KEY_SIG"
python3 billboard/billboard.py admin_init_contract $PROJECT_ROOT/test_data/user_addr $PROJECT_ROOT/test_data/user_addr_sig