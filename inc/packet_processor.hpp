#pragma once
#include "inc/util.hpp"
#include "inc/dns_util.hpp"

/* Callback function for processing a packet */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/* Function for processing DNS data */
void process_dns_packet(const struct pcap_pkthdr *header, const u_char *packet);
