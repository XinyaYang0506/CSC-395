# SANDBOX
This program blocks system calls called by the child program. 

## List of default blocked sys call: 
- **open, openat:** with O_RDONLY, O_WRONLY or O_RDWR flag;
- **unlink:** remove hard links or files;
- **chdir:** change the current working directory;
- **mkdir:** create a directory;
- **rmdir:** remove a directory;
- **socket:** create an endpoint for communication;
- **kill, tkill, tgkill, sigqueue:** send signals to other process;
- **exec:** replace the current process image with a new process image;
- **fork, vfork, clone:** create child process. 

## How to use sandbox
First, use ```make``` to compile sandbox. The users should use command line to type in their config. There are 6 flags the users can use to allow certain sys calls. 
- ```-r dir```: allow open or openat the files under dir or its sub-directories in RDONLY mode; 
- ```-w dir```: allow open or openat the files under dir or its sub-directories in WRONLY or RDWR mode; 
- ```-s```: grant socket system call; 
- ```-g```: grant kill (send signal) system call; 
- ```-e```: grant exec system call; 
- ```-f```: grant fork system call;   

Because the author is awesome, so she allows users to specify multiple directories for ```-r``` and ```-w``` by typing in ```-r dir1 -r dir2``` or ```-w dir1 dir2```. Users can have up to 100 directories for ```-r``` and ```-w``` respectively.    
Overall, if you want to run ```./test_program``` and allow open/openat ```-r``` in dir1 and dir2, open/openat ```-w``` in dir3, grant exec and kill, you should type: 
```
./sandbox -r dir1 -r dir2 -w dir3 -e -g - ./test_program
```
Wrong command line inputs will result in undefind behavior. (Please forgive the ugly ptrace kill error message if you have multi-process program. I don't have enough time implementing the book keeping of the running processes. This will be the future work.)

## Testing
You can go to ./test directory and use ```make``` to build the executables. 
- fork: There will be a parent, child, grand child process each using different system calls. Unlink, exec and open (create) can be tested here.  
- exec: exec to ls. The purpose for this test is see whether the first exec call will be ignored if exec is not allowed. 
- clone: test clone, a call similar to fork. I use the code online, so do not mind the warning.
- open: open(write) and chdir can be tested here. 

Notice that all the relative path appeeared in my test files are related to the directory sandbox is in.  
There is no especial notes, ./name should work for all of them. ```sand.c``` and ```test.c``` are used for other programs. 
I tried to sandbox emacs, ls, firefox and chromium-browser too. 

## Acknowledgement
The system call registers info is from [here](https://filippo.io/linux-syscall-table/).  
The frame of the program is provided by Charlie Curtsinger.   
The exec handling and sleep trick are inspired by Garrett Wang. 
