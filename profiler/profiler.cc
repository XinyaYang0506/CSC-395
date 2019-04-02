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
#include <memory>
#include <string>
#include <unordered_map>
#include "inspect.h"
using std::string;
using std::tuple;
using std::unique_ptr;
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
using funcMap = unordered_map<string, int>;

// general numeric constants (got from alex)
enum : size_t {
  PAGE_SIZE = 0x1000LL,
  NUM_DATA_PAGES = 256,
  PERIOD = 100000000
};

class every_perf {
 public:
  int perf_fd;
  void* buffer;
  perf_event_mmap_page* mmap_header;
  void* data;
  funcMap function_map;

  every_perf(int perf_fd) {
    this->perf_fd = perf_fd;
    buffer = mmap(nullptr, (1 + NUM_DATA_PAGES) * PAGE_SIZE,
                  PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    mmap_header = static_cast<perf_event_mmap_page*>(buffer);
    data = reinterpret_cast<void*>(reinterpret_cast<char*>(buffer) + PAGE_SIZE);
    function_map = funcMap();
    function_map.insert({"all", 0});
  }

  void add_record(string sfname) {
    funcMap::iterator got = function_map.find(sfname);
    function_map.at("all") += 1;
    if (got == function_map.end()) {
      function_map.insert({sfname, 1});
    } else {
      got->second = got->second + 1;
    }
  }

  void report() {
    int total = function_map.at("all");
    function_map.erase("all");

    std::cout << "function amount: " << function_map.size()
              << " total: " << total << std::endl;

    for (auto record : function_map) {
      std::cout << record.first << " : " << (int) (record.second * 100.0 / total)
                << "%" << std::endl;
    }
  }
};

using e_pMap = unordered_map<pid_t, every_perf>;
static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void get_next_record(struct perf_event_mmap_page* mmap_header, void* data,
                     e_pMap* e_p_map) {
  auto* event_header = reinterpret_cast<perf_event_header*>(
      static_cast<char*>(data) +
      ((mmap_header->data_tail) % (mmap_header->data_size)));
  mmap_header->data_tail += event_header->size;
  uint32_t type = event_header->type;
  // std::cout << __func__ << "::"<< __LINE__ << " record type: " << type <<
  // std::endl;
  if (type == PERF_RECORD_SAMPLE) {  // == 9
    auto* event_data = reinterpret_cast<sample_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    // std::cout << __LINE__ << " record sample" << std::endl;
    const char* fname =
        address_to_function(static_cast<pid_t>(event_data->pid),
                            reinterpret_cast<void*>(event_data->ip));
    if (fname != NULL) {
      string sfname(fname);
      pid_t tid = static_cast<pid_t>(event_data->tid);
      e_p_map->at(tid).add_record(sfname);
    }
  } else if (type == PERF_RECORD_EXIT) {  // == 4
    auto* event_data = reinterpret_cast<exit_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    pid_t tid = static_cast<pid_t>(event_data->tid);

    std::cout << "result of tid: " << tid << std::endl;
    e_p_map->at(tid).report();
    e_p_map->erase(tid);
    std::cout << __func__ << " " << __LINE__
              << " e_p_map.size() == " << e_p_map->size() << std::endl;
    if (e_p_map->empty()) {
      exit(EXIT_SUCCESS);
    }
  } else if (type == PERF_RECORD_FORK) {  // == 7
    auto* event_data = reinterpret_cast<fork_record*>(
        reinterpret_cast<char*>(event_header) + sizeof(perf_event_header));
    std::cout << __LINE__ << " fork record: pid " << event_data->pid << " "
              << "tid " << event_data->tid << std::endl;

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
    // std::cout << __LINE__ << std::endl;
    int perf_fd = perf_event_open(&attr, event_data->tid, -1, -1, 0);
    if (perf_fd == -1) {
      fprintf(stderr, "perf_event_open failed\n");
      exit(2);
    }

    e_p_map->insert({event_data->tid, every_perf(perf_fd)});
  }
}

void run_profiler(pid_t child_pid, e_pMap* e_p_map) {
  bool running = true;

  while (running) {
    std::cout << __func__ << "... " << std::endl;
    e_pMap::iterator it = e_p_map->begin();
    while (it != e_p_map->end()) {
      std::cout << __func__ << " " << __LINE__ << " tid: " << it->first
                << std::endl;
      perf_event_mmap_page* mmap_header = it->second.mmap_header;
      void* data = it->second.data;
      if (mmap_header->data_head != mmap_header->data_tail) {
        get_next_record(mmap_header, data, e_p_map);
      }
      ++it;
    }
    // for (auto& e_p : *e_p_map) {
    //   std::cout << __func__ << " " << __LINE__ << " tid: " << e_p.first
    //             << std::endl;
    //   perf_event_mmap_page* mmap_header = e_p.second.mmap_header;
    //   void* data = e_p.second.data;
    //   // std::cout << __func__ << " " << __LINE__ << " first: " << e_p.first
    //   // " second: " <<  e_p.second.data  << std::endl;
    //   if (mmap_header->data_head != mmap_header->data_tail) {
    //     get_next_record(mmap_header, data, e_p_map);
    //   }
    // }
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
    std::cout << __func__ << " " << __LINE__ << std::endl;
    e_pMap* e_p_map = new unordered_map<pid_t, every_perf>();
    e_p_map->insert({child_pid, every_perf(perf_fd)});
    // Start profiling
    run_profiler(child_pid, e_p_map);
  }

  return 0;
}
