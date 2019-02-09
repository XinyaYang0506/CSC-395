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

#include <limits.h>

int main(int argc, char **argv) {
  // Call fork to create a child process
  pid_t child_pid = fork();
  if (child_pid == -1) {
    perror("fork failed");
    exit(2);
  }

  // If this is the child, ask to be traced
  if (child_pid == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme failed");
      exit(2);
    }

    // Stop the process so the tracer can catch it
    raise(SIGSTOP);
    if (execlp(argv[1], argv[1], NULL)) {
      perror("execlp failed");
      exit(2);
    }

  } else {
    // Wait for the child to stop
    int status;
    int result;
    do {
      result = waitpid(child_pid, &status, 0);
      if (result != child_pid) {
        perror("waitpid failed");
        exit(2);
      }
    } while (!WIFSTOPPED(status));

    // We are now attached to the child process
    printf("Attached!\n");

    // Now repeatedly resume and trace the program
    bool running = true;
    int last_signal = 0;
    while (running) {
      // Continue the process, delivering the last signal we received (if any)
      if (ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) == -1) {
        perror("ptrace CONT failed");
        exit(2);
      }

      // No signal to send yet
      last_signal = 0;

      // Wait for the child to stop again
      if (waitpid(child_pid, &status, 0) != child_pid) {
        perror("waitpid failed");
        exit(2);
      }

      if (WIFEXITED(status)) {
        printf("Child exited with status %d\n", WEXITSTATUS(status));
        running = false;
      } else if (WIFSIGNALED(status)) {
        printf("Child terminated with signal %d\n", WTERMSIG(status));
        running = false;
      } else if (WIFSTOPPED(status)) {
        // Get the signal delivered to the child
        last_signal = WSTOPSIG(status);

        // If the signal was a SIGTRAP, we stopped because of a system call
        if (last_signal == SIGTRAP) {
          // Read register state from the child process
          struct user_regs_struct regs;
          if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs)) {
            perror("ptrace GETREGS failed");
            exit(2);
          }

          // Get the system call number
          size_t syscall_num = regs.orig_rax;
          int is_sys_call = 1;  // true
          switch (syscall_num) {
            case 0: {
              unsigned int fd = regs.rdi;
              size_t count = regs.rdx;
              printf("system call read with fd %u\n", fd);
              break;
            }

            case 1: {
              unsigned int fd = regs.rdi;
              size_t count = regs.rdx;
              printf("system call write with fd %u\n", fd);
              break;
            }

            case 2: {
              const char *filename = (void *)regs.rdi;
              int flags = regs.rsi;
              mode_t mode = regs.rdx;
              printf("system call open with filename %s\n", filename);
              break;
            }

            case 3: {
              unsigned int fd = regs.rdi;
              printf("system call close with fd %u\n", fd);
              break;
            }

            case 41: {
              int family = regs.rdi;
              int type = regs.rsi;
              int protocol = regs.rdx;
              printf("system call socket with type %d\n", type);
              break;
            }

            case 59: {
              const char *filename = (void *)regs.rdi;
              if (filename && strcmp(filename, argv[0]) != 0) {
                is_sys_call = false;
              } else {
                char **const argv = (void *)regs.rsi;
                char **const envp = (void *)regs.rdx;
                printf("system call execve with filename %s\n", filename);
              }

              break;
            }

            case 57: {
              printf("system call fork\n");
              break;
            }

            case 80: {
              const char *filename = (void *)regs.rdi;  // not correct
              printf("system call chdir with filename %s\n", filename);
              break;
            }

            case 83: {
              const char *pathname = (void *)regs.rdi;
              mode_t mode = regs.rsi;
              printf("system call mkdir with pathname %s\n", pathname);
              break;
            }

            case 84: {
              const char *pathname = (void *)regs.rdi;
              printf("system call rmdir with pathname %s\n", pathname);
              break;
            }

            case 62: {
              pid_t *pid = (void *)regs.rdi;
              int sig = regs.rsi;
              printf("system call kill with signal %d\n", sig);
              break;
            }

              // dont know the system call for removing the files

            default: { is_sys_call = false; }
          }

          if (is_sys_call == true) {
            printf("terminate the child process\n");
            if (kill(child_pid, SIGKILL) == -1) {
              perror("kill tracee failed");
              exit(2);
            } else {
              exit(EXIT_SUCCESS);
            }
          }

          // Print the systam call number and register values
          // The meanings of registers will depend on the system call.
          // Refer to the table at https://filippo.io/linux-syscall-table/
          // printf("Program made system call %lu.\n", syscall_num);
          // printf("  %%rdi: 0x%llx\n", regs.rdi);
          // printf("  %%rsi: 0x%llx\n", regs.rsi);
          // printf("  %%rdx: 0x%llx\n", regs.rdx);
          // printf("  ...\n");

          // char cwd[PATH_MAX];
          // if (getcwd(cwd, sizeof(cwd)) != NULL) {
          //   printf("Current working dir: %s\n", cwd);
          // } else {
          //   perror("getcwd() error");
          //   exit(2);
          //   return 1;
          // }

          last_signal = 0;
        }
      }
    }

    return 0;
  }
}
