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
#include <sys/limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>

extern char *optarg;
extern int optind, opterr, optopt;

// TODO: sometimes there will be null directory to openat, or unlink
typedef struct {
  char *read;
  char *read_write;
  bool can_socket;
  bool can_signal;
  bool can_exec;
  bool can_fork;
} permission;

const char *find_filename(pid_t child_pid, const char *filename) {
  bool string_end = false;
  int counter = 0;
  char path[PATH_MAX] = {0};
  while (!string_end && counter < PATH_MAX) {
    for (int i = 0; !string_end && i < 64; i += 8) {
      char c = (char)(ptrace(PTRACE_PEEKDATA, child_pid, filename, NULL) >>
                      i);  // why it is in reverse?
      // if (c < 32 || c > 126) {
      //   return NULL;
      // }
      if (c == '\0') {
        string_end = true;
      } else {
        path[counter] = c;
        counter++;
      }
    }
    filename += 8;
  }
  char *real_path;
  real_path = realpath(path, NULL);
  printf("PATH is %s\n", real_path);
  return real_path;
}

bool is_subdirectory(char *root, const char *dir) {
  printf("root = %s\n", root);
  if (!dir) {
    printf("Warning: system call is dealing with a null directory.\n");
    return true;  // when dir is null, it cannot change anything
  }

  if (!root) {
    return false;
  }
  while (root != NULL && dir != NULL &&
         *root != '\0') {  // not till the end of root

    if (*dir != *root) {  // there is difference between dir and root
      return false;
    }

    root++;
    dir++;
  }
  return true;
}

void check_open_flags(int flags, char *read_write, char *read,
                      const char *filename, int *should_sandbox) {
  if ((flags & O_RDWR) % 4 == 2) {
    printf("Oh this program wants to read and write!\n");
    if (read_write != NULL && is_subdirectory(read_write, filename)) {
      *should_sandbox = false;
    }
  } else if ((flags & O_WRONLY) % 2 == 1) {
    printf("Oh this program wants to write!\n");
    if (read_write != NULL && is_subdirectory(read_write, filename)) {
      *should_sandbox = false;
    }
  } else if ((flags & O_RDONLY) % 2 == 0) {
    printf("Oh this program wants to read!\n");
    if (read != NULL && is_subdirectory(read, filename)) {
      *should_sandbox = false;
    }
  }
  return;
}

int main(int argc, char **argv) {
  permission perm;
  perm.read = NULL;
  perm.read_write = NULL;
  perm.can_socket = false;
  perm.can_exec = false;
  perm.can_fork = false;
  perm.can_signal = false;

  int opt;
  while ((opt = getopt(argc, argv, "r:w:sef")) != -1) {
    switch (opt) {
      case 'r':
        perm.read =
            realpath(optarg, NULL);  // will be null if the address is invalid
        break;
      case 'w':
        perm.read_write =
            realpath(optarg, NULL);  // will be null if the address is invalid
        break;
      case ':':  //!!!!!!TODO: cannot detect missing argument
        printf("missing argument %c\n", optopt);
        break;
      case 's':
        perm.can_socket = true;
        break;
      case 'g':
        perm.can_signal = true;
        break;
      case 'e':
        perm.can_exec = true;
        break;
      case 'f':
        perm.can_fork = true;
        break;
    }
  }

  printf("child: %s\n", argv[optind + 1]);
  printf("read: %s\n", perm.read);
  printf("write: %s\n", perm.read_write);
  printf("can_exec: %d\n", perm.can_exec);
  printf("can_fork: %d\n", perm.can_fork);
  printf("can_signal: %d\n", perm.can_signal);
  printf("can_socket: %d\n", perm.can_socket);
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
    bool after_first_exec = false;
    while (running) {
      // Set the tracee to stop at the next exec and let the tracer to check
      // this status
      if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACEEXEC) ==
          -1) {
        perror("ptrace traceme failed");
        exit(2);
      }

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
      } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        printf("got the first exec\n");
        after_first_exec = true;
      } else if (after_first_exec && WIFSTOPPED(status)) {
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
          printf("rax is 0x%llx\n", regs.rax);  // it is not 0???
          printf("orig_rax is 0x%llx\n", regs.orig_rax);
          int should_sandbox = true;  // true
          switch (syscall_num) {
            case SYS_open: {  // open
              const char *filename = (void *)regs.rdi;
              int flags = regs.rsi;
              filename = find_filename(child_pid, filename);
              check_open_flags(flags, perm.read_write, perm.read, filename,
                               &should_sandbox);
              free((void *)filename);
              // mode_t mode = regs.rdx;
              printf("system call open\n");
              break;
            }

            case SYS_openat: {  // openat
              const char *filename = (void *)regs.rsi;
              int flags = regs.rdx;
              unsigned long long int return_value = regs.rax;
              filename = find_filename(child_pid, filename);
              check_open_flags(flags, perm.read_write, perm.read, filename,
                               &should_sandbox);
              free((void *)filename);
              // mode_t mode = regs.rdx;
              printf("SYS_openat is %d\n", SYS_openat);
              printf("system call openat\n");
              break;
            }

            case SYS_unlink: {  // remove file
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, filename)) {
                should_sandbox = false;
              }
              printf("system call unlink with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_chdir: {  // change directory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read, filename) ||
                  is_subdirectory(perm.read_write, filename)) {
                should_sandbox = false;
              }
              printf("system call chdir with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_mkdir: {  // make diretory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, filename)) {
                should_sandbox = false;
              }
              printf("system call mkdir with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_rmdir: {  // remove directory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, filename)) {
                should_sandbox = false;
              }
              printf("system call rmdir with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_socket: {  // socket
              if (!perm.can_socket) {
                int family = regs.rdi;
                int type = regs.rsi;
                int protocol = regs.rdx;
                printf("system call socket with type %d\n", type);
              } else {
                should_sandbox = false;
              }
              break;
            }
            case SYS_kill: {  // send signal
              pid_t *pid = (void *)regs.rdi;
              int sig = regs.rsi;
              printf("system call kill with signal %d\n", sig);
              break;
            }

            case SYS_execve: {  // exec
              if (!perm.can_exec) {
                const char *filename = (void *)regs.rdi;
                filename = find_filename(child_pid, filename);
                char **const argv = (void *)regs.rsi;
                char **const envp = (void *)regs.rdx;
                if (!filename) {
                  should_sandbox = false;
                }
                printf("system call execve\n");
              } else {
                should_sandbox = false;
              }

              break;
            }

            case SYS_fork: {  // fork
              if (!perm.can_fork) {
                printf("system call fork\n");
              } else {
                should_sandbox = false;
              }
              break;
            }

            // TODO: Find the option PTRACE_SETREGS to change the return value
            // of sys calls, but, how to know which syscall do we have when the
            // child is trying to exit?
            // TODO: The calls come in pairs! Can I use the second to tell the
            // return value?
            default: { should_sandbox = false; }
          }

          if (should_sandbox == true) {
            printf("terminate the child process\n");
            //   if (kill(child_pid, SIGKILL) == -1) {
            //     perror("kill tracee failed");
            //     exit(2);
            //   } else {
            //     exit(EXIT_SUCCESS);
            //   }
          }

          // Refer to the table at https://filippo.io/linux-syscall-table/

          last_signal = 0;
        }
      }
    }

    return 0;
  }
}
