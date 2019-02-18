CC := clang
CFLAGS := -fsanitize=address -g

all: sandbox mysh open fork

clean:
	rm -rf mysh mysh.dSYM
	rm -rf sandbox sandbox.dSYM
	rm -rf fork fork.dSYM
	rm *.log

mysh: mysh.c
	$(CC) $(CFLAGS) -o mysh mysh.c

open: open.c
	$(CC) $(CFLAGS) -o open open.c

fork: fork.c
	$(CC) $(CFLAGS) -o fork fork.c

sandbox: sandbox.c
	$(CC) $(CFLAGS) -o sandbox sandbox.c
