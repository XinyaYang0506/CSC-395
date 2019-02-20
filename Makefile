CC := clang
CFLAGS := -g

all: sandbox

clean:
	rm -rf sandbox sandbox.dSYM
	rm -f *.log


sandbox: sandbox.c
	$(CC) $(CFLAGS) -o sandbox sandbox.c

