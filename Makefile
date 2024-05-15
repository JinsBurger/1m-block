LDLIBS=-lnetfilter_queue
CXXFLAGS=-std=c++11

all: netfilter-test

netfilter-test.o: netfilter-test.c 

netfilter-test: netfilter-test.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o *.d
