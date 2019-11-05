all: netfilter_block

netfilter_block: nfqnl_test.c
	gcc -Wall -g -o  nfqnl_test nfqnl_test.c

clean:
	rm -f netfilter_block
