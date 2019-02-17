CC := clang
CFLAGS := -g -Wall -Werror

all: mysh

clean:
	rm -rf mysh mysh.dSYM

mysh: mysh.c
	$(CC) $(CFLAGS) -o mysh mysh.c
