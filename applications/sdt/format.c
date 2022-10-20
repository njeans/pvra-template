#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "appPVRA.h"
#include "command.h"


FILE *open_file(const char *const filename, const char *const mode) {
  return fopen(filename, mode);
}

int main(int argc, char **argv) {

	int ret = 0;
// 	printf("argv[0] %s\n", argv[0]);
//	printf("argv[1] %s\n", argv[1]);

	char* args[5];
	int args_index = 0;

	char* token;
	char* string;
	char* tofree;

	string = strdup(argv[1]);

	if (string != NULL) {

	  tofree = string;
      int index = 0;
	  while ((token = strsep(&string, " ")) != NULL)
	  {
	    args[args_index] = token;
	    args_index++;
	    index++;
	  }
	}


	int tid = atoi(args[0]);
	int uid = atoi(args[1]);
	int seqNo = atoi(args[2]);

	printf("\ntid: %d uid: %d seqNo: %d ", tid, uid, seqNo);

	struct private_command eCMD;

	eCMD.CI.uidx = uid;

	eCMD.CT.tid = tid;
	eCMD.seqNo = seqNo;
	if (strcmp(args[3], "-r")==0) {
	    memcpy(&eCMD.CI.recover_key, args[4], KEY_SIZE);
	    memcpy(&eCMD.CI.input_data, args[4], DATA_SIZE);
	    printf("recover_key %s\n", args[4]);
	} else if (strcmp(args[3], "-i")==0){
	    memcpy(&eCMD.CI.input_data, args[4], DATA_SIZE);
	    memcpy(&eCMD.CI.recover_key, args[4], KEY_SIZE);
	    printf("input_data %s\n", args[4]);
//	} else {
//	    printf("require -r or -i flag:\n");
//	    printf("\t-r <key> for input of a %d recovery key\n",KEY_SIZE);
//        printf("\t-i <data> for input data of input of a %d size input data\n",DATA_SIZE);
//	    ret = -1;
	}

	char* output_path = argv[2];
	FILE *sk_file = open_file(argv[2], "wb");

	if (sk_file == NULL) {
		fprintf(stderr, "fopen failed.\n");
		ret = -1;
	}

	if (fwrite(&eCMD, sizeof(struct private_command), 1, sk_file) != 1) {
		fprintf(stderr, "only partially written.\n");
		ret = -1;
	}
    free(tofree);

	fclose(sk_file);
	return ret;

}
