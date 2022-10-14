import json
import os

num_users = int(os.environ.get("NUM_USERS"))
PROJECT_ROOT = os.environ.get('PROJECT_ROOT')
pubkeys_path = PROJECT_ROOT+"/test_sgx/pubkeys.list"

with open(PROJECT_ROOT+"/billboard/accounts.json") as f:
    accounts = json.loads(f.read())

user_addresses = list(accounts["addresses"].keys())
public_key = ["" for _ in range(num_users)]
for i in range(num_users):
    address = user_addresses[i+1]  # admin is account at position 0
    print("address for user",i,
          address)

    priv = bytes(accounts["addresses"][address]["secretKey"]["data"])
    pub = bytes(accounts["addresses"][address]["publicKey"]["data"])
    public_key[i] = pub.hex() 
    with open("user"+str(i)+"_prikey.bin", "wb") as f:
        f.write(priv)
    with open("user"+str(i)+"_pubkey.bin", "wb") as f:
        f.write(pub)

with open(pubkeys_path, "w") as f:
    f.write(str(num_users) + "\n")
    f.write("\n".join(public_key))

