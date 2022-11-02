import base64
import json
import sys
import time
import requests

import auditee
from constants import *
from utils import swap_endians


def verify_ias_report():
    with open(QUOTE_FILE_PATH, "rb") as f:
        quote_bytes = f.read()
    quote_b64 = base64.b64encode(quote_bytes)
    quote_dict = {"isvEnclaveQuote": quote_b64.decode()}
    headers = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": IAS_PRIMARY_KEY,
    }
    print("[biPVRA] Sending quote to Intel's Attestation Service for verification ...")
    res = requests.post(IAS_URL, json=quote_dict, headers=headers)
    if res.ok:
        print(f"[biPVRA] Attestation report verification succeeded!")
    else:
        sys.exit(
            f"Attestatin verification failed, with status: "
            f"{res.status_code} and reason: {res.reason}\n"
            f"Did you set SGX_SPID and IAS_PRIMARY_KEY?\n"
            "See https://github.com/sbellem/sgx-iot#set-environment-variables{term.normal}"
        )
    ias_report = {"body": res.json(), "headers": dict(res.headers)}
    with open(IAS_REPORT_PATH, "w") as f:
        json.dump(ias_report, f)
    print(
        f"[biPVRA] Verify reported MRENCLAVE against trusted source code ..."
    )
    match = auditee.verify_mrenclave(PROJECT_ROOT, SIGNED_ENCLAVE_PATH, ias_report=IAS_REPORT_PATH,)
    print(
        f"[biPVRA] MRENCLAVE of remote attestation report does not match trusted source code."
    )
    print(f"[biPVRA] Extracting public key from IAS report ...")
    quote_body = res.json()["isvEnclaveQuoteBody"]
    report_data = base64.b64decode(quote_body)[368:432]
    x_little = report_data[:32]
    y_little = report_data[32:]
    x = swap_endians(x_little, length=32, from_byteorder="little", to_byteorder="big")
    y = swap_endians(y_little, length=32, from_byteorder="little", to_byteorder="big")
    point = x + y
    with open(SIGN_KEY_PATH, "wb") as f:
        f.write(point)
