default: build

build: clean
	g++ -Wall -std=c++2a -o ./bin/test ./src/main.cpp -lpcap

run: clean
	g++ -Wall -std=c++2a -o ./bin/test ./src/main.cpp -lpcap
	./bin/test $(filter-out $@,$(MAKECMDGOALS))

clean:
	rm -rf ./bin/test