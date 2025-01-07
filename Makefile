.RECIPEPREFIX = >
CC = gcc
CFLAGS = -g -Wall -Wextra -pedantic -lpthread -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
BIN_DIR = bin

all: myproxy

myproxy: ./src/myproxy.c
> $(CC) $(CFLAGS) -o $(BIN_DIR)/myproxy ./src/myproxy.c

clean:
> rm -f $(BIN_DIR)/myproxy
