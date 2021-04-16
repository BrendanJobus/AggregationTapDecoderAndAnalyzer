<!-- Title -->
# Aggregation Tap Decoder And Analyzer ##


<!-- Table of Contents -->
<details open="open">
  <summary><b>Table of Contents</b></summary>
  <ol>
    <li>
      <a href="#about-the-project"><b>About The Project</b></a>
      <ul>
        <li><a href="#description">Description</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started"><b>Getting Started</b></a>
      <ul>
	<li><a href="#install-libpcap">Install libpcap</a></li>
	<li><a href="#automatic">Automatic</a></li>
        <li><a href="#manual-steps">Manual Steps</a></li>
      </ul>
    </li>
    <li><a href="#contributers"><b>Contributers</b></a></li>
  </ol>
</details>


<!-- About The Project -->
## About The Project

### Description
Decoder of Aggregation Taps from header and analysis of data from the Aggregation Taps.


<!-- Getting Started -->
## Getting Started

### Using the binary
Use the included ```analyzer``` binary included in the bin folder for v1.0 of the programme. This can be run from the base directory with:
```sh
	./bin/analyzer
```

### Compiling and Running

#### Install libpcap
* On Ubuntu 18.04+
	```sh
	sudo apt update
	sudo apt install libpcap-dev
	```
<br/>

------
#### Automatic
##### Compile
* To compile the code, use
	```sh
	make
	```
	while in the base folder. This will compile the code into a binary called `test` in the bin folder.

##### Run
* To automatically compile and run the code, use
	```sh
	make run
	```
	while in the base folder. Which analyses all of the pcap files held in the data folder.
	
##### Anaylse a Specific pCap
* To anaylse a specific pCap, add the file location to the end of the command eg.
	```sh
	make run ./data/marketData.pcap
	```
	while in the base folder.
<br/>

------
#### Manual Steps
##### Compile
* To compile the code manually, use
	```sh
	g++ -Wall -std=c++2a -o ./bin/test ./src/main.cpp -lpcap
	```
	while in the base folder. This will compile the code into a binary called `test` in the bin folder.

##### Run
* To run the compiled code, use
	```sh
	./bin/test
	```
	while in the base folder. Which analyses all of the pcap files held in the data folder.

##### Anaylse a Specific pCap
* To anaylse a specific pCap, add the file location to the end of the command eg.
	```sh
	./bin/test ./data/marketData.pcap
	```
	while in the base folder.


<!-- Contributers -->
## Contributers
* [Alannah Henry](https://github.com/alannahhenry)
* [Brendan Jobus](https://github.com/BrendanJobus)
* [Cillian Fogarty](https://github.com/cillfog1)
* [Darren Aragones](https://github.com/ara-gone)
* [Finn Jaksland](https://github.com/jakslanf)
* [Owen Gallagher](https://github.com/gallagow)
