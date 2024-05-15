#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define LIBNET_LIL_ENDIAN 1

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"

#define IPPROTO_IPV4 0x0800
//#define IPPROTO_TCP 6
