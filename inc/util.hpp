#pragma once
#include <cstring>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "inc/util.hpp"

/* DNS port */
#define DNS_PORT 53

/* verbose logging option */
#define VERBOSE_MODE false

/* filter expression for capturing UDP packets using port 53 only */
#define CAPTURE_FILTER_EXP "udp port 53"

/* total number of packet captured with filter expression */
extern unsigned long long total_packets;
