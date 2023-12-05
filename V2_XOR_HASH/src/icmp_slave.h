#ifndef ICMP_SLAVE_H
#define ICMP_SLAVE_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PACKET_SIZE 1520
#define ICMP_HEADER_SIZE 8
#define PAYLOAD_SIZE 512
//#define XOR_KEY 0x55

unsigned short calculateChecksum(unsigned short *addr, int len);
int getRandomNumber(int min, int max);
int modeSlave(const char *serverIP, const char *fileName);

#endif /* ICMP_SLAVE_H */
