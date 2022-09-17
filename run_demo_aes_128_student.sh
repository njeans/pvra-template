test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f *
# Create the necessary files for demo
touch encrypted_student.txt
touch decrypted_student.txt

echo "Generating the encryption key ..."
../app/app --keygen_vsc\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --public-vsc-key aes128gcm.pem

echo "Generating the student JSON object and saving the encrypted data to encrypted_student.txt ..."
../app/app --create_student \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_student_file encrypted_student.txt \
    --student_name "Daniel Wong" \
    --student_uin "123456789" \
    --public-vsc-key aes128gcm.pem

echo "Adding field to student JSON object ..."
../app/app --update_student \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_student_file encrypted_student.txt \
    --update_student_field "Major" \
    --update_student_field_string_val "Computer Engineering" \
    --public-vsc-key aes128gcm.pem

echo "Loading the encrypted student JSON object"
../app/app --load_student \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --encrypted_student_file encrypted_student.txt \
    --decrypted_student_file decrypted_student.txt \
    --public-vsc-key aes128gcm.pem

echo "Decrypted student JSON object contents:"
cat decrypted_student.txt

echo "Key provisioning completed."