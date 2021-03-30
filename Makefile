default: build

build: clean
	g++ -Wall -std=c++20 -o ./bin/test ./src/main.cpp -lpcap

run: clean
	g++ -Wall -std=c++20 -o ./bin/test ./src/main.cpp -lpcap
	./bin/test $(filter-out $@,$(MAKECMDGOALS))

clean:
	rm -rf ./bin/test