#include <asm/unistd.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include "inspect.h"
using std::string;
using std::unordered_map;
struct sample_record {
  uint64_t ip;
  uint32_t pid;
  uint32_t tid;
};
// general numeric constants (got from alex)
enum : size_t { PAGE_SIZE = 0x1000LL, NUM_DATA_PAGES = 256 };

bool has_next_record(perf_event_mmap_page* mmap_header) {
  printf("data head: %llu\n", mmap_header->data_head);
  printf("data tail: %llu\n", mmap_header->data_tail);
  if (mmap_header->data_head != mmap_header->data_tail) {
    return true;
  } else {
    return false;
  }
}

void get_next_record(struct perf_event_mmap_page* mmap_header, void* data,
                     unordered_map<string, int> * function_map) {
  auto* event_header = reinterpret_cast<perf_event_header*>(
      static_cast<char*>(data) +
      ((mmap_header->data_tail) % (mmap_header->data_size)));
  mmap_header->data_tail += event_header->size;
  uint32_t type = event_header->type;

  if (type == PERF_RECORD_SAMPLE) {
    sample_record* event_data = reinterpret_cast<sample_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    const char* fname =
        address_to_function(static_cast<pid_t>(event_data->pid),
                            reinterpret_cast<void*>(event_data->ip));
    if (fname != NULL) {
      string sfname(fname);
      unordered_map<string, int>::iterator got =
          function_map->find(sfname);
      function_map->at("all") += 1;
      if (got ==  function_map->end()) {
        std::pair<string, int> record(sfname, 1);
         function_map->insert(record);
        // std::cout << record.first << " has " << record.second << "\n";
      } else {
        got->second = got->second + 1;
        // std::cout << got->first << " has " << got->second << "\n";
      }
    }
  } else if (type == PERF_RECORD_EXIT) {
    int total = function_map->at("all");
    function_map->erase("all");
    for (auto record : *function_map) {
      std::cout << record.first << " : " << (record.second * 100.0 /total) <<"%" <<std::endl;
    }
    exit(EXIT_SUCCESS);
  }
}

static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void run_profiler(pid_t child_pid, int perf_fd,
                  unordered_map<string, int> *function_map) {
  void* buffer = mmap(nullptr, (1 + NUM_DATA_PAGES) * PAGE_SIZE,
                      PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);

  perf_event_mmap_page* mmap_header =
      static_cast<perf_event_mmap_page*>(buffer);
  void* data =
      reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + PAGE_SIZE);

  bool running = true;

  // do some math to determine whether there is a new record
  while (running) {
    if (mmap_header->data_head != mmap_header->data_tail) {
      get_next_record(mmap_header, data, function_map);
    }
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr,
            "Usage: %s <command to run with profiler> [command arguments...]\n",
            argv[0]);
    exit(1);
  }

  // Create a pipe so the parent can tell the child to exec
  int pipefd[2];
  if (pipe(pipefd) == -1) {
    perror("pipe failed");
    exit(2);
  }

  // Create a child process
  pid_t child_pid = fork();

  if (child_pid == -1) {
    perror("fork failed");
    exit(2);
  } else if (child_pid == 0) {
    // In child process. Read from the pipe to pause until the parent resumes
    // the child.
    char c;
    if (read(pipefd[0], &c, 1) != 1) {
      perror("read from pipe failed");
      exit(2);
    }
    close(pipefd[0]);

    // Exec the requested command
    if (execvp(argv[1], &argv[1])) {
      perror("exec failed");
      exit(2);
    }
  } else {
    // In the parent process

    // Set up perf_event for the child process
    struct perf_event_attr pe = {
        .size = sizeof(struct perf_event_attr),
        .type = PERF_TYPE_HARDWARE,  // Count occurrences of a hardware event
        .config =
            PERF_COUNT_HW_REF_CPU_CYCLES,  // Count cycles on the CPU
                                           // independent of frequency scaling
        .sample_period = 10000000,
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID,
        .task = 1,
        .disabled = 1,        // Start the counter in a disabled state
        .exclude_kernel = 1,  // Do not take samples in the kernel
        .exclude_hv = 1,      // Do not take samples in the hypervisor
        .enable_on_exec = 1   // Enable profiling on the first exec call
    };

    int perf_fd = perf_event_open(&pe, child_pid, -1, -1, 0);
    if (perf_fd == -1) {
      fprintf(stderr, "perf_event_open failed\n");
      exit(2);
    }

    // Wake up the child process by writing to the pipe
    char c = 'A';
    write(pipefd[1], &c, 1);
    close(pipefd[1]);

    unordered_map<string, int> function_map;
    function_map.insert({"all", 0});
    // Start profiling
    run_profiler(child_pid, perf_fd, &function_map);
  }

  return 0;
}
