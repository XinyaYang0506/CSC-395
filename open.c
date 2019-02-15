#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main () {
    char filename[100] = "./ls.log";
    printf("filename address is %p\n", filename);
    if (open(filename,O_WRONLY) == -1) {
        perror("open failed");
        exit(2);
    } 
    if (unlink(filename) == -1) {
        perror("unlink failed");
        exit(2);
    } 
    printf("rdonly = %d\n", O_RDONLY);
    return 0;
}