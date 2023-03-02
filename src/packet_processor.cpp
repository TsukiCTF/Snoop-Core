#include "inc/packet_processor.hpp"

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header == nullptr || packet == nullptr)
    {
        return;
    }
    ++total_packets;

    // send the packet to DNS processor
    process_dns_packet(header, packet);
}

void process_dns_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    // check the Ethernet header
    const size_t packet_size = static_cast<size_t>(header->caplen);
    if (packet_size < sizeof(ether_header))
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Invalid Ethernet header length" << std::endl;
        return;
    }
    const auto ethernet_header = reinterpret_cast<const ether_header *>(packet);

    // check the IP header
    const auto ip_header_offset = sizeof(ether_header);
    if (packet_size < ip_header_offset + sizeof(iphdr))
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Invalid IP header length" << std::endl;
        return;
    }
    const auto ip_header = reinterpret_cast<const iphdr *>(packet + ip_header_offset);
    if (ip_header->version != 4 || ip_header->ihl < 5)
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Not an IPv4 packet" << std::endl;
        return;
    }
    const auto ip_payload_offset = ip_header_offset + (ip_header->ihl * 4); // calculating actual offset
    if (packet_size < ip_payload_offset)
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Invalid IP header length" << std::endl;
        return;
    }

    // check the UDP header
    const auto udp_header_offset = ip_payload_offset;
    if (ip_header->protocol != IPPROTO_UDP)
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Not a UDP packet" << std::endl;
        return;
    }
    if (packet_size < udp_header_offset + sizeof(udphdr))
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Invalid UDP header length" << std::endl;
        return;
    }
    const auto udp_header = reinterpret_cast<const udphdr *>(packet + udp_header_offset);
    if (ntohs(udp_header->dest) != DNS_PORT)
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Not a DNS packet" << std::endl;
        return;
    }

    // check the DNS header length
    const auto dns_header_offset = udp_header_offset + sizeof(udp_header);
    if (packet_size < dns_header_offset + DNS_HDR_LEN)
    {
        if (VERBOSE_MODE)
            std::cerr << "ERROR: Invalid DNS header length" << std::endl;
        return;
    }
    const auto dns_query_offset = dns_header_offset + DNS_HDR_LEN;

    // start of printing packet information
    std::cout << "+---------------------------------------------+" << std::endl;
    std::cout << "[Packet #" << total_packets << "]" << std::endl;

    // print src/dst MAC addresses
    char src_mac_str[ETHER_ADDR_LEN];
    char dst_mac_str[ETHER_ADDR_LEN];
    ether_ntoa_r(reinterpret_cast<const ether_addr *>(ethernet_header->ether_shost), src_mac_str);
    ether_ntoa_r(reinterpret_cast<const ether_addr *>(ethernet_header->ether_dhost), dst_mac_str);
    std::cout << "Src MAC: " << src_mac_str << std::endl;
    std::cout << "Dst MAC: " << dst_mac_str << std::endl;

    // print src/dst IP addresses
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip_str, INET_ADDRSTRLEN);
    std::cout << "Src IP: " << src_ip_str << std::endl;
    std::cout << "Dst IP: " << dst_ip_str << std::endl;

    // get the domain name
    auto dns_query_offset_copy = dns_query_offset;
    std::string domain_name = extract_domain_name(packet, &dns_query_offset_copy);

    // print the DNS query
    std::cout << "DNS query: " << domain_name << std::endl;
    std::cout << "+---------------------------------------------+" << std::endl
              << std::endl;

    // end of printing packet information
}