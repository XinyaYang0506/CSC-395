#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
  char filename[100] = "./sand.c";
  char filename2[100] = "./test";
  printf("filename address is %p\n", filename);
  if (open(filename, O_WRONLY | O_CREAT, S_IRWXU) == -1) {
    perror("open failed");
    exit(2);
  }
  if (chdir(filename2) == -1) {
    perror("chdir failed");
    exit(2);
  }
  // if (unlink(filename) == -1) {
  //     perror("unlink failed");
  //     exit(2);
  // }
  printf("rdonly = %d\n", O_RDONLY);
  return 0;
}