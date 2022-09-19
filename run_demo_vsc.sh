test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f *
# Create the necessary files for demo
touch ecdsa_pub_key.pem
touch ecdsa_priv_key.pem
touch enc_client_input.txt
touch encrypted_enclave_state.txt
touch decrypted_enclave_state.txt
touch signature_enc_data_command_file.txt


counter=0
curl https://127.0.0.1:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "init": "0000000000000000000000000000000000000000000000000000000000000000"}'


printf "\nGenerating the encryption key ...\n"
../app/app --keygen_vsc\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --public-vsc-key aes128gcm.pem



printf "\nGenerating the ECDSA key pair ...\n"
../app/app --keygen_ecdsa\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --public-ecdsa-key ecdsa_pub_key.pem \
    --private-ecdsa-key ecdsa_priv_key.pem




printf "\nGenerating an encrypted client input ...\n"
../app/app --create_client_input\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_client_input_file enc_client_input.txt \
    -client_input_uuid=0 \
    -client_input_command=0 \
    -client_input_result=0 \
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



let "counter += 1"
curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "48e5cfb37ad0532c7481ef69a09829334449cdad03fae35e77d1120b83ea2921"}'




printf "\nSigning the encrypted enclave state and client input ...\n"
../app/app --sign_enc_data_command \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --private-ecdsa-key ecdsa_priv_key.pem \
    -counter=$counter

printf "\nCalling VSC ...\n"
start_time=$(date +%s.%6N)
../app/app --call_vsc \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --public-ecdsa-key ecdsa_pub_key.pem \
    --public-vsc-key aes128gcm.pem \
    -counter=$counter
end_time=$(date +%s.%6N)
elapsed=$(echo "scale=6; $end_time - $start_time" | bc)
echo $elapsed


printf "\nGenerating an encrypted client input ...\n"
../app/app --create_client_input\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_client_input_file enc_client_input.txt \
    -client_input_uuid=1 \
    -client_input_command=0 \
    -client_input_result=0 \
    --public-vsc-key aes128gcm.pem


let "counter += 1"
curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "3718c93db32c1c801af02766e4ef4c7f696542eb6cef9ecc5051e03152ac25c4"}'


printf "\nSigning the encrypted enclave state and client input ...\n"
../app/app --sign_enc_data_command \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --private-ecdsa-key ecdsa_priv_key.pem \
    -counter=$counter

printf "\nCalling VSC ...\n"
../app/app --call_vsc \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --public-ecdsa-key ecdsa_pub_key.pem \
    --public-vsc-key aes128gcm.pem \
    -counter=$counter

printf "\nGenerating an encrypted client input ...\n"
../app/app --create_client_input\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_client_input_file enc_client_input.txt \
    -client_input_uuid=0 \
    -client_input_command=1 \
    -client_input_result=0 \
    --public-vsc-key aes128gcm.pem

let "counter += 1"
curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "4219b6b84125d5a107b98baf859f02eebfc383f35ea33c26507da24138f71e31"}'


printf "\nSigning the encrypted enclave state and client input ...\n"
../app/app --sign_enc_data_command \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --private-ecdsa-key ecdsa_priv_key.pem \
    -counter=$counter

printf "\nCalling VSC ...\n"
../app/app --call_vsc \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --encrypted_client_input_file enc_client_input.txt \
    --signature_enc_data_command_file signature_enc_data_command_file.txt \
    --public-ecdsa-key ecdsa_pub_key.pem \
    --public-vsc-key aes128gcm.pem \
    -counter=$counter

printf "\nLoading and decrypting the encrypted enclave state JSON object\n"
../app/app --load_enclave_state \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_enclave_state_file encrypted_enclave_state.txt \
    --decrypted_enclave_state_file decrypted_enclave_state.txt \
    --public-vsc-key aes128gcm.pem

printf "\nDecrypted enclave state JSON object contents:\n"
cat decrypted_enclave_state.txt
  