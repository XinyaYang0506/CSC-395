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
using std::tuple;
using std::unordered_map;
struct sample_record {
  uint64_t ip;
  uint32_t pid;
  uint32_t tid;
};

struct fork_record {
  uint32_t pid;
  uint32_t ppid;  // parent pid
  uint32_t tid;
  uint32_t ptid;  // parent tid
};

struct exit_record {
  uint32_t pid;
  uint32_t ppid;
  uint32_t tid;
  uint32_t ptid;
  uint64_t time;
};

typedef struct every_perf {
  int perf_fd;
  void* buffer;
  perf_event_mmap_page* mmap_header;
  void* data;
  unordered_map<string, int>* function_map;
} every_perf_t;

// general numeric constants (got from alex)
enum : size_t {
  PAGE_SIZE = 0x1000LL,
  NUM_DATA_PAGES = 256,
  PERIOD = 10000000000
};
static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void get_next_record(struct perf_event_mmap_page* mmap_header, void* data,
                     unordered_map<pid_t, every_perf_t*>* perf_fd_map) {
  auto* event_header = reinterpret_cast<perf_event_header*>(
      static_cast<char*>(data) +
      ((mmap_header->data_tail) % (mmap_header->data_size)));
  mmap_header->data_tail += event_header->size;
  uint32_t type = event_header->type;
  std::cout << "type: " << type << std::endl;
  if (type == PERF_RECORD_SAMPLE) {
    sample_record* event_data = reinterpret_cast<sample_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    std::cout << "69" << std::endl;
    const char* fname =
        address_to_function(static_cast<pid_t>(event_data->pid),
                            reinterpret_cast<void*>(event_data->ip));
    if (fname != NULL) {
      string sfname(fname);
      std::cout << "75" << std::endl;
      pid_t tid = static_cast<pid_t>(event_data->tid);
      std::cout << "tid: " << tid << std::endl;
      unordered_map<string, int>* function_map =
          perf_fd_map->at(tid)->function_map;
      std::cout << perf_fd_map->at(tid)->perf_fd << std::endl;
      std::cout << "80" << function_map->at("all") << std::endl;
      unordered_map<string, int>::iterator got = function_map->find(sfname);
      std::cout << "80.5" << std::endl;
      function_map->at("all") += 1;
      std::cout << "81" << std::endl;
      if (got == function_map->end()) {
        std::pair<string, int> record(sfname, 1);
        function_map->insert(record);
        std::cout << "tid: " << tid << record.first << " has " << record.second
                  << "\n";
      } else {
        got->second = got->second + 1;
        std::cout << "tid: " << tid << got->first << " has " << got->second
                  << "\n";
      }
    }
  } else if (type == PERF_RECORD_EXIT) {
    exit_record* event_data = reinterpret_cast<exit_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    pid_t tid = static_cast<pid_t>(event_data->tid);
    unordered_map<string, int>* function_map =
        perf_fd_map->at(tid)->function_map;
    int total = function_map->at("all");
    function_map->erase("all");
    for (auto record : *function_map) {
      std::cout << record.first << " : " << (record.second * 100.0 / total)
                << "%" << std::endl;
    }

    perf_fd_map->erase(tid);
    if (perf_fd_map->empty()) {
      exit(EXIT_SUCCESS);
    }
  } else if (type == PERF_RECORD_FORK) {
    fork_record* event_data = reinterpret_cast<fork_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    std::cout << "pid" << event_data->pid << " "
              << "tid" << event_data->tid << std::endl;

    // Set up perf_event for the new process
    struct perf_event_attr attr = {
        .size = sizeof(struct perf_event_attr),
        .type = PERF_TYPE_HARDWARE,  // Count occurrences of a hardware event
        .config =
            PERF_COUNT_HW_REF_CPU_CYCLES,  // Count cycles on the CPU
                                           // independent of frequency scaling
        .sample_period = PERIOD,
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID,
        .task = 1,
        .exclude_kernel = 1,  // Do not take samples in the kernel
        .exclude_hv = 1       // Do not take samples in the hypervisor
    };
    std::cout << "127" << std::endl;
    int perf_fd = perf_event_open(&attr, event_data->tid, -1, -1, 0);
    if (perf_fd == -1) {
      fprintf(stderr, "perf_event_open failed\n");
      exit(2);
    }
    std::cout << "133" << std::endl;
    unordered_map<string, int> function_map;
    function_map.insert({"all", 0});
    void* buffer = mmap(nullptr, (1 + NUM_DATA_PAGES) * PAGE_SIZE,
                        PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    perf_event_mmap_page* mmap_header =
        static_cast<perf_event_mmap_page*>(buffer);
    void* data =
        reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + PAGE_SIZE);
    std::cout << "142" << std::endl;
    every_perf_t e_p = {.perf_fd = perf_fd,
                        .buffer = buffer,
                        .mmap_header = mmap_header,
                        .data = data,
                        .function_map = &function_map};
    std::cout << "new tid" << event_data->tid << std::endl;
    std::cout << "new perf fd" << e_p.perf_fd << std::endl;
    perf_fd_map->insert({event_data->tid, &e_p});
    std::cout << "149" << std::endl;
    std::cout << perf_fd_map->at(event_data->tid)->function_map->at("all")
              << std::endl;
  }
}

void run_profiler(pid_t child_pid,
                  unordered_map<pid_t, every_perf_t*>* perf_fd_map) {
  bool running = true;

  while (running) {
    for (auto perf_record : *perf_fd_map) {
      std::cout << "159" << std::endl;
      perf_event_mmap_page* mmap_header = perf_record.second->mmap_header;
      void* data = perf_record.second->data;
      std::cout << "162" << std::endl;
      if (mmap_header->data_head != mmap_header->data_tail) {
        get_next_record(mmap_header, data, perf_fd_map);
      }
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
    struct perf_event_attr attr = {
        .size = sizeof(struct perf_event_attr),
        .type = PERF_TYPE_HARDWARE,  // Count occurrences of a hardware event
        .config =
            PERF_COUNT_HW_REF_CPU_CYCLES,  // Count cycles on the CPU
                                           // independent of frequency scaling
        .sample_period = PERIOD,
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID,
        .task = 1,
        .disabled = 1,        // Start the counter in a disabled state
        .exclude_kernel = 1,  // Do not take samples in the kernel
        .exclude_hv = 1,      // Do not take samples in the hypervisor
        .enable_on_exec = 1   // Enable profiling on the first exec call
    };

    int perf_fd = perf_event_open(&attr, child_pid, -1, -1, 0);
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

    unordered_map<pid_t, every_perf_t*> perf_fd_map;
    void* buffer = mmap(nullptr, (1 + NUM_DATA_PAGES) * PAGE_SIZE,
                        PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    perf_event_mmap_page* mmap_header =
        static_cast<perf_event_mmap_page*>(buffer);
    void* data =
        reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + PAGE_SIZE);
    every_perf_t e_p = {.perf_fd = perf_fd,
                        .buffer = buffer,
                        .mmap_header = mmap_header,
                        .data = data,
                        .function_map = &function_map};
    perf_fd_map.insert({child_pid, &e_p});
    // Start profiling
    run_profiler(child_pid, &perf_fd_map);
  }

  return 0;
}
