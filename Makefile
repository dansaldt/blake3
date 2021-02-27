build-test: blake3.o
	cc -Wall -Wextra -g -O0 bin/blake3.o main.c -o blake3

blake3.o: include/blake/blake3.h src/blake3.c
	cc -Wall -Wextra -g -O0 -c src/blake3.c -o bin/blake3.o

.PHONY: clean

clean: 
	rm bin/*.o blake3