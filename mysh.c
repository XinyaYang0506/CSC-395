#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// This is the maximum number of arguments your shell should handle for one command
#define MAX_ARGS 128

/**
 * Parse the commands from line and place the seperated arguments into argv.
 *
 * line - c_string containing a shell command and arguments
 * argv - array of strings to place line arguments into.
 */
void get_commands(char * line, char ** argv) {
  int pos = 0;
  char * strtoks = " \n\t";
  char * cur = strtok(line,strtoks);
  
  
  while (cur != NULL) {
    argv[pos] = cur;
    cur = strtok(NULL,strtoks);
    pos++;
  }
  argv[pos] = NULL;

}


/**
 * Given a line of shell commands, it executes them in a new child process.
 *
 * line - a c_string containing one line with one shell command.
 * signal - flag telling whether to run command blocking (1) or nonblocking (0)
 */
void run_process(char * line, int signal) {
  char * argv[MAX_ARGS];
  get_commands(line, argv);

  if (strcmp(argv[0], "exit") == 0) {
    exit(EXIT_SUCCESS);
  }
  
  //handle cd command
  if (strcmp(argv[0],"cd") == 0) {
    if (chdir(argv[1]) != 0) {
      perror("change dir failed");
    }
    return;
  }
  
  //run the process with execvp
  pid_t child_id = fork();
  if(child_id == 0) {
    // child (execute the arguments)
    if(execvp(argv[0], argv)) {
      perror("execvp failed");
      exit(EXIT_FAILURE);
    }
  } else {
    // parent
    if(child_id == -1) {
      perror("fork failed");
      exit(EXIT_FAILURE);
    }
    
    int wstatus = 0;
    pid_t zombie_child_id;
    
    if(!signal) {
      //handle nonblocking signal
      while((zombie_child_id = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        printf("Child process %d exited with status %d\n", zombie_child_id, wstatus);
      }
    } else {//handle blocking signal
      
      // collect any zombies from previous nonblocking calls
      while((zombie_child_id = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        printf("Child process %d exited with status %d\n", zombie_child_id, wstatus);
      }

      //wait for blocking child
      pid_t blocking_child_id = wait(&wstatus);
      printf("Child process %d exited with status %d\n", blocking_child_id, wstatus);
    }
  }
}

/** 
 * Check if every character in str is whitespace.
 *
 * str - a c_string
 * @return - a c boolean. False if not all empty chars; else True
 */
int check_empty(const char * str) {
  while(*str != '\0') {
    if(! isspace(*str)) {
      return 0;
    }
    str++;
  }
  return 1;
}

/**
 * Parse a line of shell commands, seperating multiple program calls on one line
 * (delimited by ';') into individual calls to run_process.
 *
 * line - a c_string containing some number of shell commands.
 */
void parce_line(char * line) {
  //check line not empty
  if(check_empty(line)) {
    return;
  }
  
  char * tokens = ";&"; //split commands on ';' or '&'
  char * cur_command = line;

  //get first command before a delimeter
  char * delim_pos = strpbrk(cur_command,tokens);
  //get remaining commands
  int signal;
  while (delim_pos != NULL) {
    // save the signal dictating whether to run command blockingly or not
    if(*delim_pos == '&') {
      signal = 0; //signify blocking command
    } else {
      signal = 1; //signify nonblocking command
    }
    
    //end string cur at delim_pos to isolate a single command
    *delim_pos = '\0';

    //run command
    run_process(cur_command, signal);
    
    //increment past it for next command chunck
    cur_command = delim_pos + 1;

    //get next separater
    delim_pos = strpbrk(cur_command,tokens);
  }

  //put in last command (if there is one)
  if(!check_empty(cur_command)) {
    //run last process blockingly (since there were no delimeters)
    run_process(cur_command, 1);
  } 
}


/**
 * Launch the custom shell.
 *
 * argc - number of command line arguments
 * argv - the command line arguments
 */
int main(int argc, char** argv) {
  // If there was a command line option passed in, use that file instead of stdin
  if(argc == 2) {
    // Try to open the file
    int new_input = open(argv[1], O_RDONLY);
    if(new_input == -1) {
      fprintf(stderr, "Failed to open input file %s\n", argv[1]);
      exit(1);
    }
    
    // Now swap this file in and use it as stdin
    if(dup2(new_input, STDIN_FILENO) == -1) {
      fprintf(stderr, "Failed to set new file as input\n");
      exit(2);
    }
  }
  
  char* line = NULL;    // Pointer that will hold the line we read in
  size_t line_size = 0; // The number of bytes available in line
  
  // Loop forever
  while(true) {
    // Print the shell prompt
    printf("$ ");
    
    // Get a line of stdin, storing the string pointer in line
    if(getline(&line, &line_size, stdin) == -1) {
      if(errno == EINVAL) {
        perror("Unable to read command line");
        exit(2);
      } else {
        // Must have been end of file (ctrl+D)
        printf("\nShutting down...\n");
        
        // Exit the infinite loop
        break;
      }
    }
   
    // Execute the command instead of printing it below
    parce_line(line);
  }
  
  // If we read in at least one line, free this space
  if(line != NULL) {
    free(line);
  }
  
  return 0;
}
