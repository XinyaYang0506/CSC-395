CC := clang
CFLAGS := -g -Wall -Werror

all: sandbox	mysh open fork

clean:
	rm -rf mysh mysh.dSYM
	rm -rf sanbox sandbox.dSYM
	rm *.log

mysh: mysh.c
	$(CC) $(CFLAGS) -o mysh mysh.c

open: open.c
	$(CC) $(CFLAGS) -o open open.c

fork: fork.c
	$(CC) $(CFLAGS) -o fork fork.c

sandbox: sandbox.c
	$(CC)  -o sandbox sandbox.c