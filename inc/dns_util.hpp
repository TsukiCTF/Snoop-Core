#pragma once
#include "inc/util.hpp"

/* DNS header length */
#define DNS_HDR_LEN 12

/* Maximum domain name length (253 to be exact) */
#define MAX_DOMAIN_LEN 256

/* Extract and return domain name form a raw packet */
std::string extract_domain_name(const u_char *packet, unsigned long *offset);