# Snoop (Core Functions)
Snoop is a simple yet powerful network packet analyzer that allows you to capture network packets on your network in promiscuous mode and extract DNS queries. It is designed to be easy to use, even for beginners. It is written purely in C++ using libpcap.

## Features
* Captures network packets in promiscuous mode
* Displays source and destination for MAC and IP addresses
* Extracts DNS queries from captured packets
* Currently supports Ethernet with IPv4 packets only

## Dependencies
To use Snoop, you'll need to have the Libpcap library installed on your system. You can install it by running the following command:
```
sudo apt install libpcap-dev
```

## Getting started
To compile and run Snoop, simply navigate to the project directory and run the following commands:
```
make
sudo ./main
```
Please note that Snoop requires root privilege to capture network packets in promiscuous mode.

Snoop is a great tool for network administrators, security professionals, or anyone who needs to analyze network traffic. Give it a try and see how it can help you better understand your network!

## Demo screenshot
![image](https://user-images.githubusercontent.com/32463233/222639721-e89167c9-0c9c-4bd0-b6c6-8aafa1da0341.png)

## Contributing
All contributions are welcome!
