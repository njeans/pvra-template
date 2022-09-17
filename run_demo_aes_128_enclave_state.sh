test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f *
# Create the necessary files for demo
touch encrypted_enclave_state.txt
touch decrypted_enclave_state.txt

printf "\nGenerating the encryption key ...\n"
../app/app --keygen_vsc\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --public-vsc-key aes128gcm.pem

printf "\nGenerating the enclave state JSON object and saving the encrypted data to encrypted_enclave_state.txt ...\n"
../app/app --create_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nAdding user to enclave state JSON object and saving the encrypted data to encrypted_enclave_state.txt ...\n"
../app/app --add_user_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nAdding user to enclave state JSON object and saving the encrypted data to encrypted_enclave_state.txt ...\n"
../app/app --add_user_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nAdding user to enclave state JSON object and saving the encrypted data to encrypted_enclave_state.txt ...\n"
../app/app --add_user_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nLoading the encrypted enclave state JSON object\n"
../app/app --load_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --decrypted_enclave_state_file decrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nDecrypted enclave state JSON object contents:\n"
cat decrypted_enclave_state.txt

printf "\nKey provisioning completed.\n"