all: netfilter_block

netfilter_block: main.cpp
	gcc -Wall -g -o  netfilter_block main.cpp

clean:
	rm -f netfilter_block
