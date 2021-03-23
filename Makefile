default: build run clean

build:
	g++ ./src/main.cpp -lpcap -o test

run:
	./test

clean:
	rm -rf test