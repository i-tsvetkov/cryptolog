CC ?= gcc
CXX = g++
CXXFLAGS += -std=c++11 -Wall -Wno-sign-compare -I./polarssl/include

all: main

main: main.cpp xtea.o blowfish.o CryptoLog/*
	$(CXX) $(CXXFLAGS) xtea.o blowfish.o main.cpp -o main

blowfish.o: polarssl/library/blowfish.c
	$(CC) $(CXXFLAGS) -c polarssl/library/blowfish.c

xtea.o: polarssl/library/xtea.c
	$(CC) $(CXXFLAGS) -c polarssl/library/xtea.c

clean:
	rm -f xtea.o blowfish.o main

