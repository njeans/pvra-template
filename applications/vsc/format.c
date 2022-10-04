#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "appPVRA.h"
#include "command.h"


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

    printf("%d\n", (int)count);

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
	    args[args_index] = atoi(token);
	    args_index++;
	  }

	  free(tofree);
	}


	printf("%d %d %d %d", args[0], args[1], args[2], args[3]);
	int tid = args[0];
	int uid = args[1];
	int test_result = args[2];
	int seqNo = args[3];

	struct private_command eCMD;

	eCMD.CI.test_result = test_result;
	eCMD.CI.uid = uid;
	eCMD.CT.tid = tid;
	eCMD.seqNo = seqNo;


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

	fclose(sk_file);
	return ret;

}
