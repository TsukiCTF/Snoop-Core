
#include "inc/util.hpp"
#include "inc/dns_util.hpp"

std::string extract_domain_name(const u_char *packet, unsigned long *offset)
{
    std::string name;
    unsigned long pos = *offset;
    bool first = true;

    // as raw packets differentiate the names with the length of the next word in bytes,
    // "." ASCII character need to be manually added
    while (packet[pos] != 0)
    {
        if (!first)
        {
            name += '.';
        }
        else
        {
            first = false;
        }
        int label_len = packet[pos++];
        for (int i = 0; i < label_len; i++)
        {
            name += packet[pos++];
        }
    }

    // update the offset to point to the next byte after the domain name
    if (*offset == pos)
    {
        (*offset)++;
    }
    else
    {
        (*offset) += (name.length() + 1);
    }

    return name;
}