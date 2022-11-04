
import billboard

for i in range(1,7):
    num_users = 2**i
    num_users=64
    print("num_users", num_users)
    billboard.NUM_ACCOUNTS=num_users
    billboard.admin_init_contract("test_data/"+str(num_users)+"/user_addr", "test_data/"+str(num_users)+"/user_addr_sig")
    for j in range(min(10,num_users)):
        billboard.user_verify_info(j+1, audit_num=1)
        billboard.user_add_data_bb(j+1, "test_data/user_"+str(j)+"_data")
    ga = billboard.admin_post_audit_data("test_data/"+str(num_users)+"/audit_data", "test_data/"+str(num_users)+"/audit_data_sig")
    with open("eval/admin_audit.txt", "a") as f:
        eval_data = str(num_users) + "," + str(ga) + "\n"
        f.write(eval_data)
    g=billboard.user_audit(1, audit_num=1)
    for j in range(min(10,num_users)):
        with open("eval/user_audit.txt", "a") as f:
            eval_data = str(num_users) + "," + str(g) + "\n"
            f.write(eval_data)
    exit(0)

