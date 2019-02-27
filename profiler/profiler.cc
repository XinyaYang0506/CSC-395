#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void run_profiler(pid_t child_pid, int perf_fd) {

    struct perf_event_mmap_page * p;
  mmap(p, sizeof(page)*17, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
 uint_64 data_tail = p->data_tail;
  
  // Instead of profiling, just wait for the child to exit
  int status;
  while(waitpid(child_pid, &status, 0) != -1 && !WIFEXITED(status) && !WIFSIGNALED(status)) {
  uint_64 data_head = p->data_head;
  // do some math to determine whether there is a new record
  if (has_next_record){
    //get that chunk of data
    //parse it
    //get the thread id and instruction pointer
    //record the function name
    //bye
  }
  
  }

  // Print the count of events from perf_event
  printf("\nProfiler Output:\n");
  
  long long count;
  read(perf_fd, &count, sizeof(long long));
  printf("  ref cycles: %lld\n", count);
}

int main(int argc, char** argv) {
  if(argc < 2) {
    fprintf(stderr, "Usage: %s <command to run with profiler> [command arguments...]\n", argv[0]);
    exit(1);
  }

  // Create a pipe so the parent can tell the child to exec
  int pipefd[2];
  if(pipe(pipefd) == -1) {
    perror("pipe failed");
    exit(2);
  }

  // Create a child process
  pid_t child_pid = fork();

  if(child_pid == -1) {
    perror("fork failed");
    exit(2);
  } else if(child_pid == 0) {
    // In child process. Read from the pipe to pause until the parent resumes the child.
    char c;
    if(read(pipefd[0], &c, 1) != 1) {
      perror("read from pipe failed");
      exit(2);
    }
    close(pipefd[0]);

    // Exec the requested command
    if(execvp(argv[1], &argv[1])) {
      perror("exec failed");
      exit(2);
    }
  } else {
    // In the parent process

    // Set up perf_event for the child process
    struct perf_event_attr pe = {
      .size = sizeof(struct perf_event_attr),
      .type = PERF_TYPE_HARDWARE,             // Count occurrences of a hardware event
      .config = PERF_COUNT_HW_REF_CPU_CYCLES, // Count cycles on the CPU independent of frequency scaling
      .sample_period = 10000000,
      .disabled = 1,                          // Start the counter in a disabled state
      .inherit = 1,                           // Processes or threads created in the child should also be profiled
      .exclude_kernel = 1,                    // Do not take samples in the kernel
      .exclude_hv = 1,                        // Do not take samples in the hypervisor
      .enable_on_exec = 1                     // Enable profiling on the first exec call
    };

    int perf_fd = perf_event_open(&pe, child_pid, -1, -1, 0);
    if(perf_fd == -1) {
      fprintf(stderr, "perf_event_open failed\n");
      exit(2);
    }

    // Wake up the child process by writing to the pipe
    char c = 'A';
    write(pipefd[1], &c, 1);
    close(pipefd[1]);

    // Start profiling
    run_profiler(child_pid, perf_fd);
  }

  return 0;
}

