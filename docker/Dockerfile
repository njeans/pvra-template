##############################################################################
#                                                                            #
#                            Demo base                                       #
#                                                                            #
##############################################################################
FROM ubuntu:20.04 AS demo-base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y software-properties-common libssl-dev \
    build-essential \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    wget \
    libssl-dev \
    git \
    cmake \
    perl \
    libssl-dev \
	libcurl4-openssl-dev \
	protobuf-compiler \
	libprotobuf-dev \
	debhelper \
	cmake \
	reprepro \
	unzip \
	pkgconf \
	libboost-dev \
	libboost-system-dev \
	libboost-thread-dev \
	protobuf-c-compiler \
	libprotobuf-c-dev \
	lsb-release \
	libsystemd0

# Python 3.9
RUN apt-get install -y \
                python3.9 \
                python3.9-dev \
                python3-pip \
                git \
                wget \
        && rm -rf /var/lib/apt/lists/*

# symlink python3.9 to python
RUN cd /usr/bin \
    && ln -s pydoc3.9 pydoc \
    && ln -s python3.9 python \
    && ln -s python3.9-config python-config

# pip
# taken from:
# https://github.com/docker-library/python/blob/4bff010c9735707699dd72524c7d1a827f6f5933/3.10-rc/buster/Dockerfile#L71-L95
ENV PYTHON_PIP_VERSION 21.0.1
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/29f37dbe6b3842ccd52d61816a3044173962ebeb/public/get-pip.py
ENV PYTHON_GET_PIP_SHA256 e03eb8a33d3b441ff484c56a436ff10680479d4bd14e59268e67977ed40904de

RUN set -ex; \
	\
    apt-get update; \
	wget -O get-pip.py "$PYTHON_GET_PIP_URL"; \
	echo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum --check --strict -; \
	\
	python get-pip.py \
		--disable-pip-version-check \
		--no-cache-dir \
		"pip==$PYTHON_PIP_VERSION" \
	; \
	pip --version; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \
			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \
		\) -exec rm -rf '{}' +; \
	rm -f get-pip.py

# Solidity compliler
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get install -y solc

# docker cli
# RUN set -ex; \
#     \
#     apt-get update; \
#     apt-get install -y \
#         apt-transport-https \
#         ca-certificates \
#         curl \
#         gnupg \
#         lsb-release;
# RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
#         gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# RUN echo \
#     "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
#   $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# RUN apt-get update && apt-get install -y docker-ce-cli

WORKDIR /
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /linux-sgx
RUN git checkout sgx_2.17
RUN make preparation
RUN cp external/toolset/ubuntu20.04/* /usr/local/bin
# RUN cp external/dcap_source/QuoteVerification/sgxssl/Linux/package/include/* /opt/sgxsdk/include
RUN which ar as ld objcopy objdump ranlib

RUN make sdk_install_pkg USE_OPT_LIBS=0
RUN echo -e 'no\n/opt/intel' | ./linux/installer/bin/sgx_linux_x64_sdk_2.17.100.3.bin
RUN echo 'source /opt/intel/sgxsdk/environment' >> /root/.bashrc
RUN make psw_install_pkg
RUN make deb_local_repo
RUN echo "deb [trusted=yes arch=amd64] file:/linux-sgx/linux/installer/deb/sgx_debian_local_repo focal main" >> /etc/apt/sources.list;
RUN apt-get update && apt-get install -y --no-install-recommends libsgx-epid \
                    libsgx-launch \
                    libsgx-quote-ex \
                    libsgx-urts;

WORKDIR /opt/intel/
RUN cp /opt/intel/sgxsdk/SampleCode/SampleAttestedTLS/prepare_sgxssl.sh .
RUN ./prepare_sgxssl.sh

# # SGX PSW
# ENV INTEL_SGX_URL "https://download.01.org/intel-sgx"
# RUN set -eux; \
#     url="$INTEL_SGX_URL/sgx_repo/ubuntu"; \
#     echo "deb [arch=amd64] $url focal main" \
#                 | tee /etc/apt/sources.list.d/intel-sgx.list; \
#     wget -qO - "$url/intel-sgx-deb.key" | apt-key add -; \
#     apt-get update; \
#     apt-get install -y --no-install-recommends \
#                 libsgx-headers \
#                 libsgx-ae-epid \
#                 libsgx-ae-le \
#                 libsgx-ae-pce \
#                 libsgx-enclave-common \
#                 libsgx-enclave-common-dev \
#                 libsgx-epid \
#                 libsgx-epid-dev \
#                 libsgx-uae-service \
#                 libsgx-urts; \
#     rm -rf /var/lib/apt/lists/*;

# install nix
ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install --yes git curl wget sudo xz-utils
RUN groupadd --gid $GID --non-unique photon \
    && useradd --create-home --uid $UID --gid $GID --non-unique --shell /bin/bash photon \
    && usermod --append --groups sudo photon \
    && echo "photon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/photon \
    && mkdir -p /etc/nix \
    && echo 'sandbox = false' > /etc/nix/nix.conf

ENV USER photon
USER photon

WORKDIR /home/photon

#COPY --chown=photon:photon ./nix.conf /home/photon/.config/nix/nix.conf

# RUN curl -L https://nixos.org/nix/install | sh

# RUN . /home/photon/.nix-profile/etc/profile.d/nix.sh && \
#   nix-channel --add https://nixos.org/channels/nixos-21.11 nixpkgs && \
#   nix-channel --update

# ENV NIX_PROFILES "/nix/var/nix/profiles/default /home/photon/.nix-profile"
# ENV NIX_PATH /home/photon/.nix-defexpr/channels
# ENV NIX_SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt
# ENV PATH /home/photon/.nix-profile/bin:$PATH

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

ENV PATH="/home/photon/.local/bin:${PATH}"

# gen_ca_bundle
RUN mkdir enclave
COPY --chown=photon:photon scripts/utils.py scripts/utils.py
COPY --chown=photon:photon shared/ccf/sandbox_common/nodecert.pem .
RUN python scripts/utils.py gen_ca_bundle nodecert.pem enclave/ca_bundle.h
RUN rm nodecert.pem

##############################################################################
#                                                                            #
#                            Build enclave (trusted)                         #
#                                                                            #
##############################################################################
FROM  nixpkgs/nix AS build-enclave

WORKDIR /usr/src

ARG APP_NAME=heatmap
ENV APP_NAME $APP_NAME

ARG SGX_MODE=HW
ENV SGX_MODE $SGX_MODE

COPY common /usr/src/common/
COPY enclave /usr/src/enclave
COPY interface /usr/src/interface
COPY makefile /usr/src/makefile
COPY trustedLib /usr/src/trustedLib
COPY applications/$APP_NAME/*.c enclave/
COPY applications/$APP_NAME/*.h enclave/
COPY --from=demo-base /home/photon/enclave/ca_bundle.h enclave/ca_bundle.h

COPY nix /usr/src/nix
COPY nix/$SGX_MODE.nix /usr/src/default.nix

# RUN nix-build

##############################################################################
#                                                                            #
#                            Build app (untrusted)                           #
#                                                                            #
##############################################################################
FROM demo-base AS build-app

RUN apt-get update && apt-get install -y \
                autotools-dev \
                automake \
                xxd \
                iputils-ping \
                libssl-dev \
                vim \
                git \
        && rm -rf /var/lib/apt/lists/*

ARG APP_NAME=heatmap
ENV APP_NAME $APP_NAME

WORKDIR /usr/src/$APP_NAME

ENV SGX_SDK /opt/intel/sgxsdk
ENV SGXSSL_SDK /opt/intel/sgxssl
ENV PATH $PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH $SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH $SGX_SDK/sdk_libs

COPY app/ app/
COPY enclave/ enclave/
COPY applications/$APP_NAME/*.c enclave/
COPY applications/$APP_NAME/*.h enclave/
COPY applications/$APP_NAME/*.h app/
COPY common/ common/
COPY interface/ interface/
COPY nix/ nix/
COPY makefile makefile
#COPY auditee/* .
COPY trustedLib/ trustedLib/
COPY --from=demo-base /home/photon/enclave/ca_bundle.h enclave/ca_bundle.h

ARG SGX_MODE=HW
ENV SGX_MODE $SGX_MODE

ARG SGX_DEBUG=0
ENV SGX_DEBUG $SGX_DEBUG

RUN make untrusted

##############################################################################
#                                                                            #
#                            Demo runtime                                    #
#                                                                            #
##############################################################################
FROM demo-base

ARG APP_NAME=heatmap
ENV APP_NAME $APP_NAME

ARG NUM_USERS=4
ENV NUM_USERS $NUM_USERS
ENV PROJECT_ROOT="/home/photon/${APP_NAME}"
ENV deployment_location=DOCKER
ARG CCF_ENABLE=1
ENV CCF_ENABLE $CCF_ENABLE

ENV SGX_SDK /opt/intel/sgxsdk
ENV SGXSSL_SDK /opt/intel/sgxssl
ENV LD_LIBRARY_PATH $SGX_SDK/sdk_libs
ENV PATH $PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH $SGX_SDK/pkgconfig

RUN mkdir -p $PROJECT_ROOT/test_sgx/client
RUN mkdir -p $PROJECT_ROOT/test_sgx/host
RUN mkdir -p $PROJECT_ROOT/bin

COPY --from=initc3/linux-sgx:2.17.1 --chown=photon:photon /opt/intel/sgxsdk /opt/intel/sgxsdk/
COPY --from=initc3/linux-sgx:2.17.1 --chown=photon:photon /opt/intel/sgxssl /opt/intel/sgxssl/

# COPY --from=build-enclave --chown=photon:photon /usr/src/result/bin/enclave.signed.so $PROJECT_ROOT/bin/enclave.signed.so
# COPY --from=build-app --chown=photon:photon /usr/src/$APP_NAME/bin/app $PROJECT_ROOT/bin/app

WORKDIR /home/photon/$APP_NAME

COPY --chown=photon:photon makefile makefile
COPY --chown=photon:photon trustedLib trustedLib
COPY --chown=photon:photon solidity solidity
COPY --chown=photon:photon common common
COPY --chown=photon:photon interface interface
COPY --chown=photon:photon app app
COPY --chown=photon:photon enclave enclave
COPY --chown=photon:photon scripts scripts
COPY --chown=photon:photon applications/$APP_NAME/*.h app/
COPY --chown=photon:photon applications/$APP_NAME/*.h enclave/
COPY --chown=photon:photon applications/$APP_NAME/*.c enclave/
COPY --chown=photon:photon applications/$APP_NAME/*.py scripts
COPY --from=demo-base --chown=photon:photon /home/photon/enclave/ca_bundle.h enclave/ca_bundle.h

COPY --chown=photon:photon ./shared/ccf/sandbox_common/nodecert.pem ccf/
COPY --chown=photon:photon ./shared/ccf/sandbox_common/service_cert.pem ccf/
COPY --chown=photon:photon ./shared/ccf/sandbox_common/user0_cert.pem ccf/
COPY --chown=photon:photon ./shared/ccf/sandbox_common/user0_privk.pem ccf/

RUN make clean && make

WORKDIR /home/photon/$APP_NAME/scripts

CMD python demo.py