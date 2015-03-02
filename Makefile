CC  ?= gcc
CPPC = g++
CPPFLAGS += -Wall -Wno-sign-compare -I./polarssl/include

all: main

main: xtea.o blowfish.o
	$(CPPC) $(CPPFLAGS) xtea.o blowfish.o main.cpp -o main

blowfish.o: blowfish.c
	$(CC) $(CPPFLAGS) -c blowfish.c

xtea.o: xtea.c
	$(CC) $(CPPFLAGS) -c xtea.c

clear:
	rm -f xtea.o blowfish.o main

