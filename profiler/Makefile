CXX := clang++
CXXFLAGS := --std=c++11 -g -Wall $(shell pkg-config --libs --cflags libelf++ libdwarf++)

all: profiler

clean:
	rm -rf profiler

profiler: profiler.cc inspect.h
	$(CXX) $(CXXFLAGS) -o $@ $^

inspect: inspect.cc
	$(CXX) $(CXXFLAGS) -o $@ $^

