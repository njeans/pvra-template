# PVRA Template

<!-- ABOUT THE PROJECT -->
## About The Project

PVRA (Publically Verifiable Remote Attestation) aims to provide a framework for developers to bootstrap a range of auditting capabilities and security properties for their enclave based applications that are otherwise vulnerable.

The goal of this template is to provide a clean interface with PVRA framework components and an intuitive means of writing these applications. We have four example applications to showcase: VirtualStatusCard, HeatMap, EVoting, and SecureDataTransfer. To browse the trace of a PVRA application refer to ```./applications/```. VSC is currently at 229 LoC and HeatMap at 205 LoC.

## Quick Start
Run an existing application in docker with CCF in SGX simulation mode

* set Environment variables

```bash
export PROJECT_ROOT=$(pwd)
export CCF_ENABLE=1
export SGX_SPID=None
export IAS_PRIMARY_KEY=None
export APP_NAME=<sdt or heatmap or vsc>
export SGX_MODE=SW
```
* Set ```NUM_USERS```
    * sdt functionality tests requires 5 users: ```export NUM_USERS=5```
    * heatmap expects 4 users ```export NUM_USERS=4```
    * vsc expects 8 users: ```export NUM_USERS=8```

* build and deploy ccf, bulletin board, and pvra docker images

```bash
cd $PROJECT_ROOT
./setup.sh -a $APP_NAME
cd $PROJECT_ROOT/docker
./build_deploy.sh
```

## Getting Started

### How to write a PVRA application:

There are three application-specific files that need to be modified for implementing an application.

1. ```appPVRA.h``` This is the header file for the application; it defines the types of commands the enclave processes, the structure of command inputs/outputs, and the structure of application data.

2. ```appPVRA.c``` This is enclave executable application code. Every command should have an associated execution kernel. There are two auxillary functions that are required: 

   - [ ] ```initES()``` initializes the application data structures
   - [ ] write application commands and set `NUM_COMMANDS`
     - must use function signature `struct cResponse pvraCommandName(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)`
     - optional: add admin specific commands by defining `NUM_ADMIN_COMMANDS` in `appPVRA.h` and initializing them to the end of function list
   - [ ] ```initFP()``` which associates functions to enumerated commands (COMMAND<sub>0</sub>-COMMAND<sub>NUM_COMMANDS+NUM_ADMIN_COMMANDS</sub>);
   - optional: user accounts auditing with merkle tree by setting ```#define MERKLE_TREE``` in `appPVRA.h`
     - [ ] ```get_user_leaf``` generate a list of leaf nodes structs for each user account. Each leaf node should contain `uidx` field cooresponding to the `uidx` input into PVRA commands. 

3. ```application.py``` This is a python file that specifies generates user input data and admin input data for deploying the application

   - [ ] ```get_test_data``` Returns data for testing application functionality
   - [ ] ```get_test_data_omission``` Returns data for testing data omission scenarios
   - [ ] ```format_command``` convert test data to serialized C `struct private_command`.
   - [ ] ```print_cResponse``` convert serialized C `struct cResponse` to a printable python string
   - optional: user accounts auditing with merkle tree by setting ```constants.MERKLE(True)``` in `application.py`
     - [ ] ```print_leaf``` convert serialized C struct generated by ```get_user_leaf``` to a printable python string
     - [ ] ```get_leaf```  convert serialized C struct generated by ```get_user_leaf``` to a python dictionary (with `uidx` field)


### How to compile and run a PVRA application:


#### Prerequisites

* Environment variables

```bash
export PROJECT_ROOT=$(pwd)
export CCF_ENABLE=<0 or 1>
export SGX_SPID=<SGX_SPID>
export IAS_PRIMARY_KEY=<IAS_PRIMARY_KEY>	
export NUM_USERS=<NUM_USERS>
export APP_NAME=<APP_NAME>
export SGX_MODE=<HW or SW>
```

* CCF node certificates are hardcoded in the enclave image as a root of trust and must be updated in `enclave/ca_bundle.sh` In order to run the demo without SCS protection, one can ```export CCF_ENABLE=0```._

* In order to run an existing application pass the APP_NAME to ```./setup.sh``` script.
  
    * ```setup.sh``` takes as arguments ```-a <APP_NAME>``` the name of the directory in `$PROJECT_ROOT/application`. If no arguments are passed it uses the VSC application. ```--clean``` undoes the effects of the script._

```bash
./setup.sh -a $APP_NAME
```

#### Running

##### Use Docker & Docker-Compose

* For more than 9 users change value after ```"--accounts"``` to desired number of users + 1 (extra account is admin) in [docker/docker-compose.yml](docker/docker-compose.yml#L27)
* Hardware mode
```bash
export SGX_MODE=HW
cd $PROJECT_ROOT/docker
./build.sh
```

* Simulation mode
```bash
export SGX_MODE=SW
cd $PROJECT_ROOT/docker
./deploy.sh
```

##### Locally
* python3.8 or 3.9, sgxsdk, and docker, solidity compiler required

```bash
pip3 install -r requirements.txt
export SGX_SDK=/opt/intel/sgxsdk #or your local sgx sdk path
export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs:$LD_LIBRARY_PATH
export SGX_MODE=<HW or SW>
cd $PROJECT_ROOT/scripts
./build_deploy_local.sh
```

#### Run python scripts

* run demo with ```get_test_data``` output
    ```bash
    python demo.py demo <optional: NUM_USERS>
    ```
* run test with ```get_test_data``` output (checks the expected responses and leaf nodes for correctness)
    ```bash
    python demo.py test <optional: NUM_USERS> <optional: test case name>
    ```
  * see [vsc/application.py](applications/vsc/application.py#L15) for example with test case names
* run data omission demo with ```get_test_data_omission``` output
    ```bash
    python demo.py data_omission_demo <optional: NUM_USERS>
    ```

### Cleanup

```bash
cd $PROJECT_ROOT
make clean
```

#### Stop docker containers

* Docker/Local deployment

```bash
cd $PROJECT_ROOT/docker
docker-compose down
```

### Useful scripts
* `setup.sh` : setup application specific files


* `scripts/build.sh` copy relevant application files and build the enclave and untrusted host (works when building locally and in docker container)
* `scripts/copy.sh` copy relevant application files
* `scripts/build_deploy_local.sh` build CCF image, setup a docker containers for bulletin board and CCF nodes, build pvra binaries and run demo locally
* `scripts/deploy_local.sh` setup a docker containers for bulletin board and CCF nodes, build pvra binaries and run demo locally

* `docker/build_ccf.sh` : builds state continuity CCF images
* `docker/build_pvra.sh` : builds pvra image
* `docker/deploy_ccf.sh` : deploy 3 node state continuity CCF network
    * runs a virtual/sgx enclave based on `SGX_MODE` environment variable (default is SW)
* `docker/deploy_pvra.sh` : deploy pvra image and runs default demo `python demo.py`
    * runs a simulation/hardware enclave based on `SGX_MODE` environment variable (default is SW)
* `docker/run_pvra.sh` : run pvra docker container
    * runs a simulation/hardware enclave based on `SGX_MODE` environment variable (default is SW)
    * `docker/run_pvra.sh <cmd>` runs <cmd> with the docker container
      * ex: `./run_pvra.sh bash` opens bash terminal in pvra docker container
      * ex: `./run_pvra.sh "python demo.py test 2"` runs demo in test mode with 2 users in pvra docker container
  
* `docker/build.sh` : combines `build_ccf.sh` and `build_pvra.sh`
* `docker/build_deploy.sh` : combines `build.sh` and `deploy_pvra.sh`
* `docker/build_run.sh` : combines `build.sh` and `run_pvra.sh`
* `docker/deploy.sh` : combines `deploy_ccf.sh` and `deploy_pvra.sh`
* `docker/run.sh` : combines `deploy_ccf.sh` and `run_pvra.sh`
### Sample VSC Run: TODO update