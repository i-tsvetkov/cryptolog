CC ?= gcc
CXX = g++
CXXFLAGS += -Wall -Wno-sign-compare -I./polarssl/include

all: main

main: xtea.o blowfish.o
	$(CXX) $(CXXFLAGS) xtea.o blowfish.o main.cpp -o main

blowfish.o: blowfish.c
	$(CC) $(CXXFLAGS) -c blowfish.c

xtea.o: xtea.c
	$(CC) $(CXXFLAGS) -c xtea.c

clean:
	rm -f xtea.o blowfish.o main

