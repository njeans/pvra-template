# PVRA Template

<!-- ABOUT THE PROJECT -->
## About The Project

PVRA (Publically Verifiable Remote Attestation) aims to provide a framework for developers to bootstrap a range of auditting capabilities and security properties for their enclave based applications that are otherwise vulnerable.

The goal of this template is to provide a clean interface with PVRA framework components and an intuitive means of writing these applications. We have four example applications to showcase: VirtualStatusCard, HeatMap, EVoting, and SDT. To browse the trace of a PVRA application refer to ```./applications/```. VSC is currently at 153 LoC and HeatMap at 171 LoC.

## Getting Started

### How to write a PVRA application:

There are five application-specific files that need to be modified for implementing an application.

1. ```appPVRA.h``` This is the header file for the application; it defines the types of commands the enclave processes, the structure of command inputs/outputs, and the structure of application data.

2. ```appPVRA.c``` This is enclave executable application code. Every command should have an associated execution kernel. There are two auxillary functions that are required: ```initES()``` which initializes the application data structures, and ```initFP()``` which associates functions to enumerated commands (COMMAND<sub>0</sub>-COMMAND<sub>N</sub>);

3. ```host.sh``` This is a script that defines the untrusted host or enclave administrator's behavior. In the examples provides the simple host waits for client commands, executes them, and returns the associated cResponses.

4. ```client.sh``` This is a script that defines the client behavior. It is mainly setup for testing purposes, to simulate multiple client commands in a sequence sent to the host for execution.

5. ```format_command``` This is a C program executable that takes as input space-deliminated arguements, places them in a private_command struct and outputs the raw binary information ready for encryption. The result is fed to the ```encrypt_command``` executable which AES-128-GCM encrypts the binary file.




### How to compile and run a PVRA application:


#### Prerequisites

In order to run an existing application pass the APP_NAME to ```./setup.sh``` script.

- [ ] Add python requirements, make, gcc, etc.


#### Usage

```
Terminal 1:
./setup.sh -a|--app <APP_NAME> -c|--ccf <CCF_PATH>
make clean
make
export CCF_ENABLE=<0 or 1>
export SGX_SPID=<SGX_SPID>
export IAS_PRIMARY_KEY=<IAS_PRIMARY_KEY>
./admin.sh

cd ./test_sgx/host
./host.sh

Terminal 2:
cd ./test_sgx/client
./client.sh
```
**NOTE:** setup.sh with no arguments uses VSC application and sources my local CCF directory (assuming CCF is running which it usually is)

**NOTE:** setup.sh --clean to undo effects of the script

**NOTE:** CCF_pubkey is hardcoded in enclave image as a root of trust, this must be updated in enclave/initPVRA.c to reflect the live CCF pubkey

**\[TODO\]\[AUDITEE\]:** admin.sh sources a python venv for auditee, give instructions on how to setup that python environment and isolate that from admin.sh script

**\[TODO\]\[AUDITEE\]:** MRENCLAVE MATCH FROM DOCKER BUILD

**\[TODO\]\[ACCESSIBILITY\]:** make available ./debug/aes/encrypt.c and ./debug/aes/format.c for generation of ```encrypt_command``` and ```format_command``` executables OR EVEN BETTER, MAKE these files completely seamless and adaptive to struct clientCommand 

Sample VSC Run:

![alt text](./readme/setup.png)

![alt text](./readme/admin.png)

![alt text](./readme/host.png)

![alt text](./readme/client.png)

