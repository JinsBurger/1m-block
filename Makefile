LDLIBS=-lnetfilter_queue
CXXFLAGS=-std=c++11

all: 1m-block

1m-block.o: 1m-block.cpp

1m-block: 1m-block.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o *.d
