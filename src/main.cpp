#include <csignal>
#include "inc/packet_processor.hpp"

pcap_t *handle;        /* Session handle */
pcap_if_t *interfaces; /* Device interfaces */
struct bpf_program fp; /* The compiled filter expression */

/* Handle the lifecycle of packet capturing */
int packet_capture();

/* Signal handler function*/
void handle_sigint(int sig);

/* Clean up resources */
void clean_up();

/* Entry point to the program */
int main()
{
    std::signal(SIGINT, handle_sigint); // handle abrupt close by user
    return packet_capture();
}

int packet_capture()
{
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string*/
    pcap_if_t *interfaces, *current; /* Current device interface */
    char *dev;                       /* Device interface to use */
    bpf_u_int32 net;                 /* The IPv4 address of our capturing device */
    bpf_u_int32 mask;                /* The netmask of our capturing device */

    // find all device interfaces
    if (pcap_findalldevs(&interfaces, errbuf) == -1 || interfaces == nullptr)
    {
        std::cerr << "Couldn't find default device: " << errbuf << std::endl;
        return -1;
    }

    // use the first device interface in the available list
    current = interfaces;
    dev = current->name;

    // open the session in promiscuous mode (requires privilege)
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return -1;
    }

    // *** NOTICE ***
    // for now, assume that our device supply Ethernet headers
    // possible improvements to support other headers in the future
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        std::cerr << "Device " << dev << " doesn't provide Ethernet headers - not supported" << std::endl;
        return -1;
    }

    // get IPv4 address and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        std::cerr << "Can't get netmask for device " << dev << std::endl;
        net = 0;
        mask = 0;
    }

    // copmile and apply the "filter rule" for capturing
    if (pcap_compile(handle, &fp, CAPTURE_FILTER_EXP, 0, net) == -1)
    {
        std::cerr << "Couldn't parse filter " << CAPTURE_FILTER_EXP << ": " << pcap_geterr(handle) << std::endl;
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "Couldn't install filter " << CAPTURE_FILTER_EXP << ": " << pcap_geterr(handle) << std::endl;
        return -1;
    }

    // Start capturing packets
    int res = pcap_loop(handle, -1, process_packet, nullptr);
    if (res == PCAP_ERROR_BREAK)
    {
        std::cerr << "Capture loop terminated by pcap_breakloop" << std::endl;
    }
    else if (res == PCAP_ERROR)
    {
        std::cerr << "pcap_loop returned error: " << pcap_geterr(handle) << std::endl;
    }

    clean_up();
    return 0;
}

void handle_sigint(int sig)
{
    clean_up();
    std::exit(0);
}

void clean_up()
{
    std::cout << "Cleaning up ..." << std::endl;
    if (&fp != nullptr)
    {
        pcap_freecode(&fp);
    }
    if (handle != nullptr)
    {
        pcap_close(handle);
    }
    if (interfaces != nullptr)
    {
        pcap_freealldevs(interfaces);
    }
}