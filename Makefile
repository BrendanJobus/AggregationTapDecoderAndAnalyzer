default: build

build: clean
	clang++ -Wall -o test ./src/main.cpp

run: clean
	clang++ -Wall -o test ./src/main.cpp
	./test

clean:
	rm -rf test

test: build
	./test