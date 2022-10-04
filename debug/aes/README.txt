gcc aesgcm.c -o encrypt_command -lssl -lcrypto && ./encrypt_command 0 0 1 0 0

gcc encrypt.c -o encrypt_command -lssl -lcrypto 



cp ../../applications/vsc/appPVRA.h .
cp ../../enclave/enclavestate.h .
gcc format.c -o format