Install dependency: sudo apt install libpcap-dev
Compiling: g++ -I . src/util.cpp src/dns_util.cpp src/packet_processor.cpp src/main.cpp -o main -lpcap
Running: sudo ./main
