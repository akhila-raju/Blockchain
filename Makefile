CFLAGS = -g -Wall -Wno-unused-function -Werror
LDFLAGS =
LDLIBS = -lcrypto -lssl

all: balances genkey

balances: balances.o block.o common.o transaction.o
genkey: genkey.o common.o

balances.o: balances.c block.h common.h transaction.h
block.o: block.c block.h common.h transaction.h
common.o: common.c common.h
genkey.o: genkey.c common.h
transaction.o: transaction.c common.h transaction.h

clean:
	rm -f balances genkey *.o

.PHONY: all clean
