test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f *
# Create the necessary files for demo
touch input.txt
touch encrypted.txt
touch decrypted.txt
echo 'This is some decrypted text for testing' > input.txt

echo "Contents of the input file to be encrypted:"
cat input.txt

echo "Generating the encryption key ..."
../app/app --keygen_vsc\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --public-vsc-key aes128gcm.pem

echo "Encrypting the input file contents and saving to encryption.txt ..."
../app/app --encrypt_aes \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encryptedfile encrypted.txt \
    --decryptedfile input.txt \
    --public-vsc-key aes128gcm.pem

echo "Encrypting the encryption.txt contents and saving to decryption.txt ..."
../app/app --decrypt_aes \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encryptedfile encrypted.txt \
    --decryptedfile decrypted.txt \
    --public-vsc-key aes128gcm.pem
  
echo "Contents of the decrypted file (should be same as the input file):"
cat decrypted.txt

echo "Key provisioning completed.\n"