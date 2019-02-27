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
#include <time.h>

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

const char *find_filename(pid_t cur_pid, const char *filename) {
  bool string_end = false;
  int counter = 0;
  char path[PATH_MAX] = {0};
  while (!string_end && counter < PATH_MAX) {
    for (int i = 0; !string_end && i < 64; i += 8) {
      char c = (char)(ptrace(PTRACE_PEEKDATA, cur_pid, filename, NULL) >>
                      i);  // reverse because it is not littleendian, why?
                           // because it is intel
      if (c != '\0' &&
          (c < 32 || c > 126)) {  // corner case handling for first exec
        printf("Warning: system call is dealing with a null directory.\n");
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
  char *real_path;
  real_path = realpath(path, NULL);
  if (!real_path) {
    printf("Warning: system call is dealing with a null directory.\n");
  }
  printf("REAL PATH is %s\n", real_path);  // if real path is null, then path
                                           // does not exist, and it is allowed
  return real_path;
}

bool is_subdirectory(char *root[MAX_DIR], const int counter, const char *dir) {
  if (!dir) {
    return true;  // when dir is null, it cannot change anything
  }
  for (int i = 0; i < counter; i++) {
    char *cur_root = root[i];
    const char *cur_dir = dir;
    if (cur_root) {
      while (*cur_root != '\0') {     // not till the end of root
        if (*cur_dir != *cur_root) {  // if chars are different
          break;                      // go to the next element in the array
        }
        cur_root++;
        cur_dir++;
      }
      if (*cur_root == '\0') {  // sucess to the end of root
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
    } else {
      printf("open/openat is not allowed to RDWR in this directory\n");
    }
  } else if ((flags & O_WRONLY) % 2 == 1) {
    printf("Oh this program wants to write!\n");
    if (is_subdirectory(perm.read_write, perm.counter_read_write, filename)) {
      *should_sandbox = false;
    } else {
      printf("open/openat is not allowed to write in this directory\n");
    }
  } else if ((flags & O_RDONLY) % 2 == 0) {
    printf("Oh this program wants to read!\n");
    if (is_subdirectory(perm.read, perm.counter_read, filename)) {
      *should_sandbox = false;
    } else {
      printf("open/openat is not allowed to read in this directory\n");
    }
  } else {
    printf("open/openat does not read/write\n");
    *should_sandbox = false;
  }
  return;
}

void flag_choice(int argc, char **argv, permission *perm) {
  int opt;
  opterr = 0;
  while ((opt = getopt(argc, argv, "r:w:sgef")) && opt != -1) {
    printf("opt = %c %d\n", opt, opt);
    printf("optind = %d\n", optind);
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
    printf("...\n");
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

void quit(permission *perm, pid_t *pids, int pids_counter,
          int terminate_counter) {
  if (terminate_counter != pids_counter) {
    for (int i = 0; i < pids_counter; i++) {
      if (kill(*(pids + i), SIGKILL) == -1) {
        printf("kill tracee %d failed", *(pids + i));
        perror("");
        exit(2);
      }
    }
  }
  for (int i = 0; i < perm->counter_read; i++) {
    free(perm->read[i]);
  }
  for (int i = 0; i < perm->counter_read_write; i++) {
    free(perm->read_write[i]);
  }
  free(pids);
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  // initialize permission config struct
  permission perm;
  perm.can_socket = false;
  perm.can_exec = false;
  perm.can_fork = false;
  perm.can_signal = false;
  perm.counter_read = 0;
  perm.counter_read_write = 0;

  // get the config
  flag_choice(argc, argv, &perm);
  printf("...\n");

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

  } else {  // parent
    printf("sandbox parent ID is %d\n", getpid());

    // Wait for the child to stop
    int status;
    do {
      if (waitpid(child_pid, &status, 0) != child_pid) {
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
    // Set the tracee to stop at exec and fork.
    // let the tracer to check this status
    if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
               PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEVFORK) == -1) {
      perror("ptrace exec.fork failed");
      exit(2);
    }

    // Continue the process, and set the child-pid to stop when there is a
    // sys-call
    if (ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) == -1) {
      perror("ptrace CONT failed");
      exit(2);
    }

    // create a arraylist for the dependent processes (to kill them later)
    pid_t *pids = (pid_t *)malloc(sizeof(pid_t));
    printf("pids = %lu \n", sizeof(pids));
    int pids_counter = 1;
    int terminate_counter = 0;
    *pids = child_pid;
    pid_t cur_pid = child_pid;
    while (running) {
      // No signal to send yet
      last_signal = 0;

      // Wait for the child to stop again
      cur_pid = waitpid(-1, &status, 0);
      if (cur_pid == -1) {
        perror("waitpid2 failed");
        exit(2);
      }
      printf("cur_pid: %d\n", cur_pid);

      // check the status of the stopped process
      if (WIFEXITED(status)) {
        printf("Child %d exited with status %d\n", cur_pid,
               WEXITSTATUS(status));
        // terminate the sandbox program only if all the child progran have
        // terminated or exit
        terminate_counter++;
        // printf("check counters: term = %d, pids = %d", terminate_counter,
        //        pids_counter);
        if (terminate_counter == pids_counter) {
          quit(&perm, pids, pids_counter, terminate_counter);
        }
      } else if (WIFSIGNALED(status)) {
        printf("Child %d terminated with signal %d\n", cur_pid,
               WTERMSIG(status));
        // terminate the sandbox program only if all the child progran have
        // terminated or exit
        terminate_counter++;
        if (terminate_counter == pids_counter) {
          quit(&perm, pids, pids_counter, terminate_counter);
        }
      } else {
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
          printf("got the first exec\n");
          after_first_exec = true;
        } else if ((status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) ||
                   (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) ||
                   (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))) {
          if (!perm.can_fork) {  // if the creation of new process is not
                                 // allowed
            printf("fork/vfork/clone is not allowed.\n");
            quit(&perm, pids, pids_counter, terminate_counter);
          } else {  // if allowed
            // enlarge the pids arraylist, update the counter, and store the new
            // process pid
            pids = (pid_t *)realloc(pids, sizeof(pid_t) * (pids_counter + 1));
            unsigned long temp_pid = 0;  // deal with wierd data type ptrace use
            ptrace(PTRACE_GETEVENTMSG, cur_pid, NULL, &temp_pid);
            *(pids + pids_counter) = (int)temp_pid;
            printf("got fork with pid !!!!!!!!!!!!!!!!!!!!!!!! %d\n",
                   *(pids + pids_counter));

            // sleep for 0.05s to let ptrace be able to detect the new process
            struct timespec req = {0, 50000000};
            nanosleep(&req, NULL);

            // let tracer traces the child of the child
            if (ptrace(PTRACE_SETOPTIONS, *(pids + pids_counter), NULL,
                       PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEVFORK) == -1) {
              perror("ptrace fork failed");
              exit(2);
            }
            // restart the new process
            if (ptrace(PTRACE_SYSCALL, *(pids + pids_counter), NULL,
                       last_signal) == -1) {
              perror("ptrace CONT new_pid failed");
              exit(2);
            }

            // update counter
            pids_counter++;
          }
        } else if (after_first_exec && WIFSTOPPED(status)) {
          // After the first exec, start to catch system calls

          // Get the signal delivered to the child
          last_signal = WSTOPSIG(status);

          // If the signal was a SIGTRAP, we stopped because of a system call
          if (last_signal == SIGTRAP) {
            // Read register state from the child process
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, cur_pid, NULL, &regs)) {
              perror("ptrace GETREGS failed");
              exit(2);
            }

            // Get the system call number
            size_t syscall_num = regs.orig_rax;
            // printf("sys call num is %zu\n", syscall_num);

            // forgive me for the return syscall attempts
            // printf("rax is 0x%llx\n", regs.rax);  // it is not 0???
            // printf("orig_rax is 0x%llx\n", regs.orig_rax);

            int should_sandbox = true;
            // determine the sys-call, and take actions accordingly
            switch (syscall_num) {
              case SYS_open: {
                const char *filename = (void *)regs.rdi;
                int flags = regs.rsi;
                filename = find_filename(cur_pid, filename);
                printf("system call open, file: %s\n", filename);
                check_open_flags(flags, perm, filename, &should_sandbox);
                free((void *)filename);
                break;
              }

              case SYS_openat: {
                const char *filename = (void *)regs.rsi;
                int flags = regs.rdx;
                filename = find_filename(cur_pid, filename);
                printf("system call openat, file: %s\n", filename);
                check_open_flags(flags, perm, filename, &should_sandbox);
                free((void *)filename);
                break;
              }

              case SYS_unlink: {
                const char *filename = (void *)regs.rdi;
                filename = find_filename(cur_pid, filename);
                printf("system call unlink, file %s\n", filename);
                if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                    filename)) {
                  should_sandbox = false;
                } else {
                  printf("unlink is not allowed in this directory\n");
                }
                free((void *)filename);
                break;
              }

              case SYS_chdir: {
                const char *filename = (void *)regs.rdi;
                filename = find_filename(cur_pid, filename);
                printf("system call chdir, file %s\n", filename);
                if (is_subdirectory(perm.read, perm.counter_read, filename) ||
                    is_subdirectory(perm.read_write, perm.counter_read_write,
                                    filename)) {
                  should_sandbox = false;
                } else {
                  printf("chdir is not allowed in this directory\n");
                }
                free((void *)filename);
                break;
              }

              case SYS_mkdir: {
                const char *filename = (void *)regs.rdi;
                filename = find_filename(cur_pid, filename);
                printf("system call mkdir, file: %s\n", filename);
                if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                    filename)) {
                  should_sandbox = false;
                } else {
                  printf("mkdir is not allowed in this directory\n");
                }
                free((void *)filename);
                break;
              }

              case SYS_rmdir: {
                const char *filename = (void *)regs.rdi;
                filename = find_filename(cur_pid, filename);
                printf("system call rmdir with filename %s\n", filename);
                if (is_subdirectory(perm.read_write, perm.counter_read_write,
                                    filename)) {
                  should_sandbox = false;
                } else {
                  printf("rmdir is not allowed in this directory\n");
                }
                free((void *)filename);
                break;
              }

              case SYS_socket: {
                if (!perm.can_socket) {
                  printf("system call socket is not allowed\n");
                } else {
                  printf("system call socket\n");
                  should_sandbox = false;
                }
                break;
              }
              case SYS_tkill:
              case SYS_tgkill:
              case SYS_rt_sigqueueinfo:
              case SYS_rt_tgsigqueueinfo:
              case SYS_kill: {  // send signal
                if (!perm.can_signal) {
                  pid_t pid = regs.rdi;
                  if (pid == cur_pid) {
                    printf("system call kill family\n");
                    should_sandbox = false;  // allow signal to itself
                  } else {
                    int sig = regs.rsi;
                    printf("system call kill family is not allowed\n");
                    printf("This kill is to pid %d with signal %d\n", pid, sig);
                  }
                } else {
                  printf("system call kill family\n");
                  should_sandbox = false;
                }
                break;
              }

              case SYS_execve: {  // exec
                printf("system call execve\n");
                const char *filename = (void *)regs.rdi;
                filename = find_filename(cur_pid, filename);
                if (perm.can_exec) {
                  should_sandbox = false;
                } else if (!filename) {
                  should_sandbox = false;  // allow exec to a non-exist
                                           // directory
                } else {
                  printf("system call execve is not allowed \n");
                }
                free((void *)filename);
                break;
              }

                // The corpse of original fork handling
                // case SYS_vfork:
                // case SYS_clone:
                // case SYS_fork: {  // fork
                //   printf("system call fork\n");
                //   if (!perm.can_fork) {
                //   } else {
                //     should_sandbox = false;
                //   }
                //   break;
                // }

                // TODO: Find the option PTRACE_SETREGS to change the return
                // value of sys calls, but, how to know which syscall do we
                // have when the child is trying to exit?
                // TODO: The calls come in pairs! Can I use the second to tell
                // the return value?
              default: { should_sandbox = false; }
            }
            if (should_sandbox == true) {
              quit(&perm, pids, pids_counter, terminate_counter);
            }
            last_signal = 0;
            printf("...\n");
          } else {
            printf("warning: some unknown signal!\n");
          }
        }

        // Continue the current process, delivering the last signal we received
        // (if any) from any tracee processes
        if (ptrace(PTRACE_SYSCALL, cur_pid, NULL, last_signal) == -1) {
          perror("ptrace CONT failed");
          exit(2);
        }
      }
    }
    return 0;
  }
}
