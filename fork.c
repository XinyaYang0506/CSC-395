#include <asm/unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
  printf("I am a fork program\n");

  // Call fork to create a child process
  pid_t child_pid = fork();
  if (child_pid == -1) {
    perror("fork failed");
    exit(2);
  }

  //   // If this is the child, ask to be traced
  if (child_pid == 0) {
    printf("fork child is %d\n", getpid());
    // if (execlp("ls", "ls", NULL)) {
    //   perror("execlp failed");
    //   exit(2);
    // }
  } else {
    printf("fork parent is %d\n", getpid());
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
    //    execlp("./open", "./open", NULL);
  }
  return 0;
}