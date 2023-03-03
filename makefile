# Define variables for compiler and linker flags
CXX = g++
CXXFLAGS = -I . -Wall
LDFLAGS = -lpcap

# Define source files and output executable
SRCS = src/util.cpp src/dns_util.cpp src/packet_processor.cpp src/main.cpp
TARGET = main

# Define build rule for executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $(TARGET)

# Define phony targets for cleaning and rebuilding
.PHONY: clean rebuild

clean:
	rm -f $(TARGET)

rebuild: clean $(TARGET)

