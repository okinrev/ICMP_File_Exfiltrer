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

// la fonction de calcul du checksum
unsigned short calculateChecksum(unsigned short *addr, int len)
{
  unsigned int sum = 0;
  unsigned short answer = 0;

  while (len > 1)
  {
    sum += *addr++;
    len -= 2;
  }

  if (len == 1)
  {
    *(unsigned char *)&answer = *(unsigned char *)addr;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
}

// obtenir un nombre aléatoire entre min et max
int getRandomNumber(int min, int max)
{
  return rand() % (max - min + 1) + min;
}

// la fonction main du slave
int modeSlave(const char *serverIP, const char *fileName)
{
  FILE *file = fopen(fileName, "rb");
  if (file == NULL)
  {
    perror("File open failed");
    return 1;
  }

  fseek(file, 0, SEEK_END);
  long fileSize = ftell(file);
  fseek(file, 0, SEEK_SET);

  int totalChunks = (fileSize + PAYLOAD_SIZE - 1) / PAYLOAD_SIZE;

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0)
  {
    perror("socket creation failed");
    fclose(file);
    return 1;
  }

  struct sockaddr_in destAddr;
  memset(&destAddr, 0, sizeof(destAddr));
  destAddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, serverIP, &(destAddr.sin_addr)) <= 0)
  {
    perror("inet_pton failed");
    close(sockfd);
    fclose(file);
    return 1;
  }

  char packet[PACKET_SIZE];
  struct icmphdr *icmpHeader = (struct icmphdr *)packet;

  int chunkNumber = 0;
  int bytesRead;

  // generation aléatoire du CID et TID
  srand(time(NULL));
  unsigned int cid = getRandomNumber(1000, 9999);
  unsigned int tid = getRandomNumber(1000, 9999);

  char payload[PAYLOAD_SIZE];

  while ((bytesRead = fread(payload, 1, PAYLOAD_SIZE, file)) > 0)
  {
    memset(packet, 0, sizeof(packet));

    // prépare le packet ICMP echo request
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->checksum = 0;
    icmpHeader->un.echo.id = getpid();
    icmpHeader->un.echo.sequence = 0;
    icmpHeader->checksum =
        calculateChecksum((unsigned short *)icmpHeader, ICMP_HEADER_SIZE);

    // prépare la metadata
    unsigned int num = chunkNumber; // Nombre de fragments
    unsigned int total = totalChunks; // Nombre total de fragments

    // ajoute la metadata au packet
    memcpy(packet + ICMP_HEADER_SIZE, &cid, sizeof(cid));
    memcpy(packet + ICMP_HEADER_SIZE + sizeof(cid), &tid, sizeof(tid));
    memcpy(packet + ICMP_HEADER_SIZE + sizeof(cid) + sizeof(tid), &num,
           sizeof(num));
    memcpy(packet + ICMP_HEADER_SIZE + sizeof(cid) + sizeof(tid) + sizeof(num),
           &total, sizeof(total));

    // ajoute le payload au packet
    memcpy(packet + ICMP_HEADER_SIZE + (4 * sizeof(unsigned int)), payload,
           bytesRead);

    // update la taille total du packet
    unsigned int packetSize =
        ICMP_HEADER_SIZE + (4 * sizeof(unsigned int)) + bytesRead;

    // update ICMP checksum
    icmpHeader->checksum =
        calculateChecksum((unsigned short *)icmpHeader, packetSize);

    // envoie le ICMP echo request
    if (sendto(sockfd, packet, packetSize, 0, (struct sockaddr *)&destAddr,
               sizeof(destAddr))
        <= 0)
    {
      perror("sendto failed");
      close(sockfd);
      fclose(file);
      return 1;
    }

    printf("ICMP echo request sent!\n");
    printf("Sent chunk %d of %d\n", chunkNumber + 1, totalChunks);

    chunkNumber++;
  }

  fclose(file);
  close(sockfd);
  return 0;
}
