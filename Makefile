default: build

build: clean
	g++ -Wall -o ./bin/test ./src/main.cpp -lpcap

run: clean
	g++ -Wall -o ./bin/test ./src/main.cpp -lpcap
	./bin/test

clean:
	rm -rf ./bin/test