#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "appPVRA.h"


//./format_command "0 8214 1.0 1.0 10 20 0 0 0" test.bin

FILE *open_file(const char *const filename, const char *const mode) {
  return fopen(filename, mode);
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    printf("%d\n", count);

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        printf("%c\n", token);
        while (token)
        {
            //assert(idx < count); 
                printf("ERROR1\n");
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        printf("ERROR2\n");
        //assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}
struct cType 
{
	int tid;
};


struct clientCommand
{
	struct cType CT;
	struct cInputs CI;
	int seqNo;
	int cid;
};



int main(int argc, char **argv) {

	int ret = 0;

	printf("%s\n", argv[1]);

	int args[10];
	int args_index = 0;

	char* token;
	char* string;
	char* tofree;

	string = strdup(argv[1]);

	if (string != NULL) {

	  tofree = string;

	  while ((token = strsep(&string, " ")) != NULL)
	  {
	    printf("%s\n", token);
	    if(args_index == 2 || args_index == 3) {
	    	args[args_index] = atof(token);
	    }
	    else {
	    	args[args_index] = atoi(token);
	    }
	    args_index++;
	  }

	  free(tofree);
	}

	printf("%d %d %d %d %d", args[0], args[1], args[2], args[3], args[4]);
	int tid = args[0];
	int uid = args[1];
	float lat = args[2];
	float lng = args[3];
	int startTs = args[4];
	int endTs = args[5];
	bool result = (args[6]==0? false : true);
	int seqNo = args[7];
	int cid = args[8];


	struct clientCommand CC;

	CC.CI.uid = uid;
	CC.CI.data.result = result;
	CC.CI.data.lat = lat;
	CC.CI.data.lng = lng;
	CC.CI.data.startTs = startTs;
	CC.CI.data.endTs = endTs;

	CC.CT.tid = tid;
	CC.seqNo = seqNo;
	CC.cid = cid;

	char* output_path = argv[2];
	FILE *sk_file = open_file(argv[2], "wb");

	if (sk_file == NULL) {
		fprintf(stderr, "fopen failed.\n");
		ret = -1;
	}

	if (fwrite(&CC, sizeof(struct clientCommand), 1, sk_file) != 1) {
		fprintf(stderr, "only partially written.\n");
		ret = -1;
	}

	fclose(sk_file);
	return ret;

}
