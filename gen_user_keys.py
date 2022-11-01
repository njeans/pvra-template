import json
import os

num_users = int(os.environ.get("NUM_USERS"))
PROJECT_ROOT = os.environ.get('PROJECT_ROOT')
pubkeys_path = PROJECT_ROOT+"/test_sgx/pubkeys.list"

with open(PROJECT_ROOT+"/billboard/accounts.json") as f:
    accounts = json.loads(f.read())

user_addresses = list(accounts["addresses"].keys())
public_key = ["" for _ in range(num_users+1)]
for i in range(num_users+1):
    address = user_addresses[i]

    priv = bytes(accounts["addresses"][address]["secretKey"]["data"])
    pub = bytes(accounts["addresses"][address]["publicKey"]["data"])
    public_key[i] = pub.hex()
    print("[gen_user_keys] user", i, "address", address, "pubkey", pub.hex()[:3]+"..."+pub.hex()[-3:])
    if (i == 0): # admin account at position 0
        with open("admin_prikey.bin", "wb") as f:
            f.write(priv)
        with open("admin_pubkey.bin", "wb") as f:
            f.write(pub)
    else:
        with open("user"+str(i-1)+"_prikey.bin", "wb") as f:
            f.write(priv)
        with open("user"+str(i-1)+"_pubkey.bin", "wb") as f:
            f.write(pub)

with open(pubkeys_path, "w") as f:
    f.write(str(num_users+1) + "\n")
    f.write("\n".join(public_key))

