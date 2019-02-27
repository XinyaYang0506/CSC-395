CC := clang
CFLAGS := -g

all: open fork clone exec

clean:
	rm -rf sandbox sandbox.dSYM
	rm -rf fork fork.dSYM
	rm -rf open open.dSYM
	rm -rf clone clone.dSYM
	rm -rf exec exec.dSYM

open: open.c
	$(CC) $(CFLAGS) -o open open.c

exec: exec.c
	$(CC) $(CFLAGS) -o exec exec.c

fork: fork.c
	$(CC) $(CFLAGS) -o fork fork.c

clone: clone.c
	$(CC)  -o clone clone.c