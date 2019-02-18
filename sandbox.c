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

#include <error.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>

extern char *optarg;
extern int optind, opterr, optopt;
#define MAX_DIR 3

// TODO: sometimes there will be null directory to openat, or unlink
// TODO: I cannot do tracefork, ask charlie tomorrow
typedef struct {
  char *read[MAX_DIR];
  int counter_read;
  char *read_write[MAX_DIR];
  int counter_read_write;
  bool can_socket;
  bool can_signal;
  bool can_exec;
  bool can_fork;
} permission;

const char *find_filename(pid_t child_pid, const char *filename) {
  printf("get here\n");
  bool string_end = false;
  int counter = 0;
  char path[PATH_MAX] = {0};
  while (!string_end && counter < PATH_MAX) {
    for (int i = 0; !string_end && i < 64; i += 8) {
      char c = (char)(ptrace(PTRACE_PEEKDATA, child_pid, filename, NULL) >>
                      i);  // TODO: why it is in reverse?
      if (c != '\0' && (c < 32 || c > 126)) {
        return NULL;
      }
      if (c == '\0') {
        string_end = true;
      } else {
        path[counter] = c;
        counter++;
      }
    }
    filename += 8;
  }
  printf("PATH is %s\n", path);
  char *real_path;
  real_path = realpath(path, NULL);
  if (!real_path) {
    printf("Warning: system call is dealing with a null directory.\n");
  }
  printf("REAL PATH is %s\n", real_path);
  return real_path;
}

bool is_subdirectory(char *root[MAX_DIR], const int counter, const char *dir) {
  //  printf("is_sub_dir test: %s\n", root[0]);
  if (!dir) {
    printf("Warning: system call is dealing with a null directory.\n");
    return true;  // when dir is null, it cannot change anything
  }
  printf("HERE!\n");
  for (int i = 0; i < counter; i++) {
    char *cur_root = root[i];
    const char *cur_dir = dir;
    printf("is_subdir: %s\n", cur_root);
    if (cur_root) {
      printf("is_subdir: %s\n", cur_root);
      while (*cur_root != '\0') {  // not till the end of root
        if (*cur_dir !=
            *cur_root) {  // there is difference between dir and root
                          //  printf("cur char: %c\n", *cur_root);
          break;          // go to the next element in the array
        }
        cur_root++;
        cur_dir++;
      }
      printf("get to here!\n");
      if (*cur_root == '\0') {
        printf("why are you here\n");
        return true;
      }
    }
  }
  return false;
}

void check_open_flags(int flags, permission perm, const char *filename,
                      int *should_sandbox) {
  if ((flags & O_RDWR) % 4 == 2) {
    printf("Oh this program wants to read and write!\n");
    if (is_subdirectory(perm.read_write, perm.counter_read_write, filename)) {
      *should_sandbox = false;
    }
  } else if ((flags & O_WRONLY) % 2 == 1) {
    printf("Oh this program wants to write!\n");
    if (is_subdirectory(perm.read_write, perm.counter_read_write, filename)) {
      *should_sandbox = false;
    }
  } else if ((flags & O_RDONLY) % 2 == 0) {
    printf("Oh this program wants to read!\n");
    // printf("flags test: %s\n", perm.read[0]);
    if (is_subdirectory(perm.read, perm.counter_read, filename)) {
      *should_sandbox = false;
    }
  }
  return;
}

void flag_choice(int argc, char **argv, permission *perm) {
  int opt;
  while ((opt = getopt(argc, argv, "r:w:sgef")) != -1) {
    switch (opt) {
      case 'r': {
        perm->read[perm->counter_read] =
            realpath(optarg, NULL);  // will be null if the address is invalid
        // printf("getopt, read %s, %d\n", perm.read[perm.counter_read],
        //  perm.counter_read);
        perm->counter_read = perm->counter_read + 1;
        break;
      }
      case 'w': {
        perm->read_write[perm->counter_read_write] =
            realpath(optarg, NULL);  // will be null if the address is invalid
        // printf("getopt, write %s, %d\n",
        //  perm->read_write[perm->counter_read_write],
        //  perm->counter_read_write);
        perm->counter_read_write = perm->counter_read_write + 1;
        break;
      }
      case ':':  //!!!!!!TODO: cannot detect missing argument
        printf("missing argument %c\n", optopt);
        break;
      case 's':
        perm->can_socket = true;
        break;
      case 'g':
        perm->can_signal = true;
        break;
      case 'e':
        perm->can_exec = true;
        break;
      case 'f':
        perm->can_fork = true;
        break;
    }
  }
  printf("Below are your config: \n");
  printf("child program: %s\n", argv[optind + 1]);
  for (int i = 0; i < perm->counter_read; i++) {
    printf("can_read: %s\n", perm->read[i]);
  }
  for (int i = 0; i < perm->counter_read_write; i++) {
    printf("can_write: %s\n", perm->read_write[i]);
  }
  printf("can_exec: %d\n", perm->can_exec);
  printf("can_fork: %d\n", perm->can_fork);
  printf("can_signal: %d\n", perm->can_signal);
  printf("can_socket: %d\n", perm->can_socket);
  printf("...\n");

  return;
}

int main(int argc, char **argv) {
  permission perm;
  // perm.read = [];
  // perm.read_write = [];
  perm.can_socket = false;
  perm.can_exec = false;
  perm.can_fork = false;
  perm.can_signal = false;
  perm.counter_read = 0;
  perm.counter_read_write = 0;

  flag_choice(argc, argv, &perm);
  printf("...\n");
  // printf("test 273: %d\n", perm.can_exec);
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
    printf("sandbox parent ID is %d\n", getpid());
    // Wait for the child to stop
    int status;
    int result;
    do {
      result = waitpid(child_pid, &status, 0);
      if (result != child_pid) {
        perror("waitpid1 failed");
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
      // printf("test 273: %s\n", perm.read[0]);
      // Set the tracee to stop at the next exec and let the tracer to check
      // this status
      // printf("in sandbox parent, childpid = %d\n", child_pid);
      if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
                 PTRACE_O_TRACEEXEC) == -1) {  //| PTRACE_O_TRACEFORK
        // printf("in error message child pid is %d\n", child_pid);
        perror("ptrace exec.fork failed");
        exit(2);
      }

      // Set the tracee to stop at the next dork and let the tracer to check
      // this status
      // if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACEFORK) ==
      //     -1) {
      //   perror("ptrace traceme failed");
      //   exit(2);
      // }

      // Continue the process, delivering the last signal we received (if any)
      if (ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) == -1) {
        perror("ptrace CONT failed");
        exit(2);
      }

      // No signal to send yet
      last_signal = 0;

      // Wait for the child to stop again
      if (waitpid(-1, &status, 0) == -1) {
        perror("waitpid2 failed");
        exit(2);
      }

      printf("get a signal! and afe = %d\n", after_first_exec);
      // printf("test 273: %s\n", perm.read[0]);
      if (WIFEXITED(status)) {
        printf("Child exited with status %d\n", WEXITSTATUS(status));
        running = false;
      } else if (WIFSIGNALED(status)) {
        printf("Child terminated with signal %d\n", WTERMSIG(status));
        running = false;
      } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        printf("got the first exec\n");
        after_first_exec = true;
      } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
        pid_t new_pid;
        ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &new_pid);
        printf("got fork with pid %d\n", new_pid);
      } else if (after_first_exec && WIFSTOPPED(status)) {
        // printf("get here\n");
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
          // printf("rax is 0x%llx\n", regs.rax);  // it is not 0???
          // printf("orig_rax is 0x%llx\n", regs.orig_rax);

          int should_sandbox = true;  // true
          switch (syscall_num) {
            case SYS_open: {  // open
              const char *filename = (void *)regs.rdi;
              int flags = regs.rsi;
              filename = find_filename(child_pid, filename);
              check_open_flags(flags, perm, filename, &should_sandbox);
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
              printf("test: %s \n", filename);
              check_open_flags(flags, perm, filename, &should_sandbox);
              free((void *)filename);
              // mode_t mode = regs.rdx;
              printf("system call openat\n");
              break;
            }

            case SYS_unlink: {  // remove file
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                  filename)) {
                should_sandbox = false;
              }
              printf("system call unlink with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_chdir: {  // change directory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read, perm.counter_read, filename) ||
                  is_subdirectory(perm.read_write, perm.counter_read_write,
                                  filename)) {
                should_sandbox = false;
              }
              printf("system call chdir with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_mkdir: {  // make diretory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                  filename)) {
                should_sandbox = false;
              }
              printf("system call mkdir with filename %s\n", filename);
              free((void *)filename);
              break;
            }

            case SYS_rmdir: {  // remove directory
              const char *filename = (void *)regs.rdi;
              filename = find_filename(child_pid, filename);
              if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                  filename)) {
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
              if (!perm.can_signal) {
                pid_t pid = regs.rdi;
                if (pid == child_pid) {
                  should_sandbox = false;
                } else {
                  int sig = regs.rsi;
                  printf("system call kill to pid %d with signal %d\n", pid,
                         sig);
                }
              } else {
                should_sandbox = false;
              }
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

            case SYS_vfork:
            case SYS_clone:
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
            printf("warning: sandboxxxxxxx\n");
            //   if (kill(child_pid, SIGKILL) == -1) {
            //     perror("kill tracee failed");
            //     exit(2);
            //   } else {
            //     exit(EXIT_SUCCESS);
            //   }
          }

          last_signal = 0;
          printf("...\n");
        }
      }
    }

    return 0;
  }
}
