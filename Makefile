OBJS = $(subst .cpp,.o,$(wildcard *.cpp))

TOOLCHAIN_PREFIX := 
EXTRA_CXXFLAGS := 
EXTRA_LIBS := 
OUTPUT = ctrcdnfetch
LIBS = -lcurl -lssl -lcrypto $(EXTRA_LIBS)
CXXFLAGS = -O2 -Wall -std=c++11 $(EXTRA_CXXFLAGS)
CXX = $(TOOLCHAIN_PREFIX)g++
STRIP = $(TOOLCHAIN_PREFIX)strip

#wildcard on strip and rm because if it's a g++ for windows, it will add .exe

all: $(OBJS)
	$(CXX) -o "bin/$(OUTPUT)" $(OBJS) $(LIBS)
	$(STRIP) "bin/$(OUTPUT)"*

clean:
	rm -rf "bin/$(OUTPUT)"* $(OBJS)
