#!/bin/bash
set -e
if [[ -z "${PROJECT_ROOT}" ]];
then
    echo "Error: environment variable PROJECT_ROOT not set."
    exit 1
fi

sgxssl_dir=$PROJECT_ROOT/trustedLib/intel-sgx-ssl
if [[ ! -d $sgxssl_dir/openssl_source ]];
then
    git submodule update --init
fi
openssl_ver_name=openssl-1.1.1s
if [[ ! -f $sgxssl_dir/openssl_source/$openssl_ver_name.tar.gz ]];
then
    openssl_chksum=c5ac01e760ee6ff0dab61d6b2bbd30146724d063eb322180c6f18a6f74e4b6aa
    server_url_path=https://www.openssl.org/source
    full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz
    openssl_out_dir=$sgxssl_dir/openssl_source
    cd $sgxssl_dir

    wget $full_openssl_url -P $openssl_out_dir || exit 1
    sha256sum $openssl_out_dir/$openssl_ver_name.tar.gz > $sgxssl_dir/check_sum_openssl.txt
    echo "downloading OPENSSL source code now..." 
    grep $openssl_chksum $sgxssl_dir/check_sum_openssl.txt
    if [ $? -ne 0 ]; then
        echo "File $openssl_out_dir/$openssl_ver_name.tar.gz checksum failure"
        rm -f $openssl_out_dir/$openssl_ver_name.tar.gz
        exit -1
    fi
    cd $sgxssl_dir/Linux
    make clean sgxssl_no_mitigation
fi

cd $PROJECT_ROOT/docker
if [ "$CCF_ENABLE" = "1" ]; then
    ./deploy_ccf.sh
fi
docker-compose up -d billboard
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/user0*
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/member0*
cd $PROJECT_ROOT/scripts
./build.sh
cd $PROJECT_ROOT/demo
python3 demo.py $@