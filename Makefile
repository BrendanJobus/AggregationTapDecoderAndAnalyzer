default: build run clean

build:
	g++ -o test ./src/main.cpp

run:
	./test

clean:
	rm -rf test
