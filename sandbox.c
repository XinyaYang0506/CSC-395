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
#include <limits.h>
#include <sys/stat.h>
typedef struct {
  char *read;
  char *read_write;
  bool exec;
  bool fork;
} permission;

void print_filename(pid_t child_pid, const char *filename) {
  printf("charBit is %d\n", CHAR_BIT);
  printf("filename is ");
  bool string_end = false;
  while (!string_end) {
    for (int i = 64; !string_end && i > 0; i = i - 8) {
      char c = (char)(ptrace(PTRACE_PEEKDATA, child_pid, filename, NULL) >> i);
      if (c == '\0') {
        string_end = true;
      } else {
        printf("%c", c);
      }
    }
    filename += 8;
  }
  printf("\n");
  return;
}
// bool flagchoice(int argc, char *argv[argc], permission *perm) {
//   unsigned int counter;
//   for (counter = 1; argv[counter] != NULL; counter++) {
//     // Verifies if User inserted Flag
//     if (*(argv[counter]) != '-' || *(argv[counter] + 1) != '-') {
//       fprintf(stderr, "Please give a -- flag\n");
//       perror("No proper flag");
//       exit(2);
//     }

//     // Parse flags
//     if (strcmp((argv[counter] + 2), "read") { //compare the string start from
//     index 2
//       if ()
//     }
//     switch (*(argv[counter] + 1)) {
//       case 'r':
//         if (r_flag(argv, input, &counter) == false) return false;
//         break;
//       case 'w':
//         if (w_flag(argv, output, &counter) == false) return false;
//         break;
//       default:  // Informs User of invalid flag
//       {
//         fprintf(stderr, "Invalid flag.\n");
//         return false;
//       } break;
//     }  // switch
//   }    // for
//   return true;
// }

int main(int argc, char **argv) {
  permission perm;
  // flagchoice(argc, argv, &perm);
  int opt;
  while ((opt = getopt(argc, argv, ":r:w:ef")) != -1) {
    switch (opt) {
      case 'r':
        // printf("read : %s\n", optarg);
        perm.read = optarg;
        break;
      case 'w':
        // printf("read_write : %s\n", optarg);
        perm.read_write = optarg;
        break;
      case 'e':
        // printf("exec : %c\n", opt);
        perm.exec = true;
      case 'f':
        // printf("fork : %c\n", opt);
        perm.fork = true;
        break;
    }
  }

  printf("optind: %d\n", optind);
  printf("read: %s\n", perm.read);
  printf("write: %s\n", perm.read_write);
  printf("exec: %d\n", perm.exec);
  printf("fork: %d\n", perm.fork);

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

    if (execlp(argv[optind + 1], argv[optind + 1], NULL)) {
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
          printf("sys call num is %zu\n", syscall_num);
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

            case 257: {
              const char *filename = (void *)regs.rsi;
              print_filename(child_pid, filename);
              int flags = regs.rsi;
              if (flags == O_RDONLY) {
                printf("Oh this program wants to read!\n");
              } else if (flags == O_WRONLY) {
                printf("Oh this program wants to write!\n");
              } else if (flags == O_RDWR) {
                printf("Oh this program wants to read and write!\n");
              }
              // mode_t mode = regs.rdx;
              printf("system call open\n");
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
              if (!perm.exec) {
                const char *filename = (void *)regs.rdi;
                // strange error
                // print_filename(child_pid, filename);
                if (filename && strcmp(filename, argv[0]) != 0) {
                  is_sys_call = false;
                } else {
                  char **const argv = (void *)regs.rsi;
                  char **const envp = (void *)regs.rdx;
                  printf("system call execve\n");
                }
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

          // if (is_sys_call == true) {
          //   printf("terminate the child process\n");
          //   if (kill(child_pid, SIGKILL) == -1) {
          //     perror("kill tracee failed");
          //     exit(2);
          //   } else {
          //     exit(EXIT_SUCCESS);
          //   }
          // }

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
