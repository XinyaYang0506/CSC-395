CXX := clang++
CXXFLAGS := -g -Wall

all: profiler

clean:
	rm -rf profiler

profiler: profiler.cc
	$(CXX) $(CXXFLAGS) -o $@ $^

