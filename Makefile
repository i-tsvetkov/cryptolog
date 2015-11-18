CC ?= gcc
CXX = g++
CXXFLAGS += -Wall -Wno-sign-compare -I./polarssl/include

all: main

main: xtea.o blowfish.o CryptoLog/*
	$(CXX) $(CXXFLAGS) xtea.o blowfish.o main.cpp -o main

blowfish.o: polarssl/library/blowfish.c
	$(CC) $(CXXFLAGS) -c polarssl/library/blowfish.c

xtea.o: xtea.c
	$(CC) $(CXXFLAGS) -c polarssl/library/xtea.c

clean:
	rm -f xtea.o blowfish.o main

