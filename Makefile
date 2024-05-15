LDLIBS=-lnetfilter_queue
CXXFLAGS=-std=c++11

all: 1m-block

netfilter-test.o: 1m-block.c 

1m-block: 1m-block.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o *.d
