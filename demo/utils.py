import sys
import hashlib
import requests
import base64
import os
import argparse

from web3 import Web3

# import auditee


def gen_ca_bundle(ca_bundle_path=None,
                    timeserver_ca_urls="https://letsencrypt.org/certs/lets-encrypt-r3.pem",
                    timeserver_ca_path=None,
                    ccf_crt_dir=None,
                    ccf_crt_files=None,
                    args=None):
    
    if args is None:
        # doing this here to prevent unnecessary dependency on constants.py
        from constants import CCF_ENABLE
        ccf_enable = CCF_ENABLE
    else:
        ccf_crt_dir = args.ccf_directory
        ccf_crt_files = args.ccf_files
        ca_bundle_path = args.ca_bundle_path
        ccf_enable = args.ccf_enable.lower() == "true" or args.ccf_enable == "1"
        timeserver_ca_path = args.timeserver_ca_path
        timeserver_ca_urls = args.timeserver_ca_url
    ccf_ca_def = ""
    if ccf_enable:
        ccf_ca_buffs = []
        if ccf_crt_files is None:
            if ccf_crt_dir is None:
                from constants import CCF_CERTS_DIR
                ccf_crt_dir = CCF_CERTS_DIR
            files = os.listdir(ccf_crt_dir)
            ccf_crt_files = [os.path.join(ccf_crt_dir, f) for f in files if "nodecert" in f]
        elif type(ccf_crt_files) != list:
            ccf_crt_files = [ccf_crt_files]
        for cert in ccf_crt_files:
            with open(cert) as f:
                buff = f.read().replace("\n", "\\r\\n\"\\\n\"")
                buff = buff[:-4]
                buff += "\\0\""
                ccf_ca_buffs.append(buff)
        ccf_ca_def = ",\\\n\"".join(ccf_ca_buffs)
        if ca_bundle_path is None:
            from constants import PROJECT_ROOT
            ca_bundle_path = os.path.join(PROJECT_ROOT, "enclave", "ca_bundle.h")
    else:
        print("Not adding CCF certs")
    timeserver_ca_buff = ""
    if timeserver_ca_path is not None:
        if os.path.isdir(timeserver_ca_path):
            files = os.listdir(timeserver_ca_path)
            timeserver_ca_files = [os.path.join(timeserver_ca_path, f) for f in files if ".pem" in f]
        else:
            if type(timeserver_ca_path) != list:
                timeserver_ca_files = [timeserver_ca_path]
            else:
                timeserver_ca_files = timeserver_ca_path
        for file in timeserver_ca_files:
            with open(file) as f:
                timeserver_ca_buff += f.read()
    else:
        if timeserver_ca_urls is None:
            timeserver_ca_urls = ["https://letsencrypt.org/certs/lets-encrypt-r3.pem"]
        elif type(timeserver_ca_urls) != list:
            timeserver_ca_urls = [timeserver_ca_urls]
        for u in timeserver_ca_urls:
            response = requests.get(u)
            timeserver_ca_buff += response.content.decode("utf-8")
    timeserver_ca_def = timeserver_ca_buff.replace("\n", "\\r\\n\"\\\n\"")

    header_buff = f'''// THIS FILE IS GENERATED BY utils.py gen_ca_bundle DONT EDIT.\n
#ifndef TRUSTED_CERTS_H
#define TRUSTED_CERTS_H   
 
#define default_ca_bundle \\
\"{timeserver_ca_def}\\0\"

const size_t num_ccf_certs = {len(ccf_ca_buffs)};
const char * ccf_certs[{len(ccf_ca_buffs)}] = \\
{{"{ccf_ca_def}}};

#endif

'''
    print(header_buff)
    with open(ca_bundle_path, "w") as f:
        f.write(header_buff)


def swap_endians(b, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, to_byteorder)


def verify_ias_report(report, report_key, report_sig):
    pass


def convert_publickey_address(publickey):
    if type(publickey) == str:
        if publickey[:2] == "0x":
            publickey = publickey[2:]
        publickey = bytes.fromhex(publickey)
    if len(publickey) == 65:
        publickey = publickey[1:]
    h = Web3.sha3(primitive=publickey)
    return Web3.toChecksumAddress(Web3.toHex(h[-20:]))


def get_packed_address(address):
    if address[:2] == "0x":
        address = address[2:]
    return bytes.fromhex(address).rjust(32, b'\0')


def get_address_from_packed(address):
    return Web3.toChecksumAddress(address[-20:].hex())


def get_cert_fingerprint(cert):
    cert = cert.lstrip("-----BEGIN CERTIFICATE-----\n").rstrip('\n-----END CERTIFICATE-----\n')
    public_bytes = base64.b64decode(cert)
    return sha256(public_bytes).hex()


# def verify_ias_report():
#     with open(QUOTE_FILE_PATH, "rb") as f:
#         quote_bytes = f.read()
#     quote_b64 = base64.b64encode(quote_bytes)
#     quote_dict = {"isvEnclaveQuote": quote_b64.decode()}
#     headers = {
#         "Content-Type": "application/json",
#         "Ocp-Apim-Subscription-Key": IAS_PRIMARY_KEY,
#     }
#     print("[biPVRA] Sending quote to Intel's Attestation Service for verification ...")
#     res = requests.post(IAS_URL, json=quote_dict, headers=headers)
#     if res.ok:
#         print(f"[biPVRA] Attestation report verification succeeded!")
#     else:
#         sys.exit(
#             f"Attestatin verification failed, with status: "
#             f"{res.status_code} and reason: {res.reason}\n"
#             f"Did you set SGX_SPID and IAS_PRIMARY_KEY?\n"
#             "See https://github.com/sbellem/sgx-iot#set-environment-variables{term.normal}"
#         )
#     ias_report = {"body": res.json(), "headers": dict(res.headers)}
#     with open(IAS_REPORT_PATH, "w") as f:
#         json.dump(ias_report, f)
#     print(
#         f"[biPVRA] Verify reported MRENCLAVE against trusted source code ..."
#     )
#     match = auditee.verify_mrenclave(PROJECT_ROOT, SIGNED_ENCLAVE_PATH, ias_report=IAS_REPORT_PATH,)
#     print(
#         f"[biPVRA] MRENCLAVE of remote attestation report does not match trusted source code."
#     )
#     print(f"[biPVRA] Extracting public key from IAS report ...")
#     quote_body = res.json()["isvEnclaveQuoteBody"]
#     report_data = base64.b64decode(quote_body)[368:432]
#     x_little = report_data[:32]
#     y_little = report_data[32:]
#     x = swap_endians(x_little, length=32, from_byteorder="little", to_byteorder="big")
#     y = swap_endians(y_little, length=32, from_byteorder="little", to_byteorder="big")
#     point = x + y
#     with open(SIGN_KEY_PATH, "wb") as f:
#         f.write(point)


def print_hex_trunc(val):
    if type(val) == bytes:
        val = val.hex()
    if val[:2] == "0x":
        val = val[2:]
    l = min(3, int(len(val)/2))
    return "0x" + val[:l]+"..."+val[-l:]


def sha256(data):
    return hashlib.sha256(data).digest()


def sha3(data):
    # m = hashlib.sha3_256()
    # m.update(data)
    # return m.digest()
    return Web3.sha3(primitive=data)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "gen_ca_bundle":
        parser = argparse.ArgumentParser(prog="gen_ca_bundle", 
        description="Generates ca_bundle.h file with hardocded certificates for time server and CCF network nodes.")
        parser.add_argument("gen_ca_bundle")
        parser.add_argument("-p", "--ca-bundle-path", type=str,
                                help="Path to generate file in")
        parser.add_argument("-tu", "--timeserver-ca-url", 
                                type=str, action='append',
                                help="Urls where time server certificates can be downloaded.")
        parser.add_argument("-tp", "--timeserver-ca-path", type=str, action='append', help="Directory with *.pem files for timeserver Ex: /etc/ssl/certs or File containing ca files for timeserver Ex: /etc/ssl/certs/ca-certificates.crt")
        parser.add_argument("-ccf-enable", type=str, default="1", help="Whether or not to add CCF certificates")
        parser.add_argument("-cd", "--ccf-directory", type=str, help="Directory containing CCF node certs. Will automatically add any files with nodecert in the name.")
        parser.add_argument("-cf", "--ccf-files", type=str, action='append',
                                    help="CCF node certs.")
        args = parser.parse_args()
        gen_ca_bundle(args=args)
    elif len(sys.argv) == 2:
        globals()[sys.argv[1]]()
    elif len(sys.argv) == 3:
        globals()[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 4:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5:
        globals()[sys.argv[1]](sys.argv[2], sys.argv[3], sys.argv[4])
