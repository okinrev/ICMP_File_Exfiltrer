#ifndef ICMP_MASTER_H
#define ICMP_MASTER_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PACKET_SIZE 1520
#define ICMP_HEADER_SIZE 8
#define PAYLOAD_SIZE 512
//#define XOR_KEY 0x55

void getTimestamp(char *timestamp, size_t size);
int modeMaster();

#endif /* ICMP_MASTER_H */
