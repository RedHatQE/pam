/*
 * Print real and effective user ID
 *
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char**argv) 
{
    FILE *file;
    char *fname="/tmp/xauthlog";
    int i;

    file = fopen("/tmp/xauthlog", "a+");
    if(file == NULL) {
        printf("Failed creating file /tmp/xauthlog");
        return -1;
    }

    printf("NECHsaPACI");

    fprintf(file, "Args: ");
    for(i = 0; i < argc-1; i++) fprintf(file, "%s ", argv[i]);
    fprintf(file, "\n");

    fprintf(file, "%d/%d\n", getuid(), geteuid()); 
    fclose(file);
    chmod("/tmp/xauthlog", 0777);
    return 0;
}
