#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
  printf("Hi! I am exec program.\n");
  if(execlp("ls", "ls", NULL)) {
      perror("execvp failed");
      exit(EXIT_FAILURE);
    }
  return 0;
}