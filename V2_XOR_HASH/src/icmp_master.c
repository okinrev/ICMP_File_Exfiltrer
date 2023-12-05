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

// timestamp format ISO 8601
void getTimestamp(char *timestamp, size_t size)
{
  time_t rawtime;
  struct tm *timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(timestamp, size, "%Y-%m-%dT%H:%M:%S", timeinfo);
}

// fonction main
int modeMaster()
{
  // crée le socket RAW ICMP
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0)
  {
    perror("socket creation failed");
    return 1;
  }

  char packet[PACKET_SIZE];
  struct sockaddr_in clientAddr;
  socklen_t clientAddrLen = sizeof(clientAddr);

  // array stockage fragments fichier recus
  unsigned char *fileChunks = NULL;
  int *chunkReceived = NULL;
  int totalChunksReceived = 0;
  int totalChunksExpected = -1;
  FILE *outputFile = NULL;

  while (1)
  {
    memset(packet, 0, sizeof(packet));

    // recevoir le ICMP echo request
    ssize_t bytesRead =
        recvfrom(sockfd, packet, sizeof(packet), 0,
                 (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (bytesRead < 0)
    {
      perror("recvfrom failed");
      close(sockfd);
      if (outputFile != NULL)
      {
        fclose(outputFile);
      }
      free(fileChunks);
      free(chunkReceived);
      return 1;
    }

    struct ip *ipHeader = (struct ip *)packet;
    struct icmp *icmpHeader = (struct icmp *)(packet + (ipHeader->ip_hl << 2));

    if (icmpHeader->icmp_type == ICMP_ECHO)
    {
      // prepare ICMP echo reply
      icmpHeader->icmp_type = ICMP_ECHOREPLY;
      icmpHeader->icmp_cksum = 0;

      // envoye ICMP echo reply
      if (sendto(sockfd, packet, bytesRead, 0, (struct sockaddr *)&clientAddr,
                 sizeof(clientAddr))
          <= 0)
      {
        perror("sendto failed");
        close(sockfd);
        return 1;
      }

      printf("ICMP echo reply sent to %s\n", inet_ntoa(clientAddr.sin_addr));

      // extraire la metadata du paquet
      unsigned int *cid =
          (unsigned int *)(packet + (ipHeader->ip_hl << 2) + ICMP_HEADER_SIZE);
      unsigned int *tid =
          (unsigned int *)(packet + (ipHeader->ip_hl << 2) + ICMP_HEADER_SIZE
                           + sizeof(unsigned int));
      unsigned int *num =
          (unsigned int *)(packet + (ipHeader->ip_hl << 2) + ICMP_HEADER_SIZE
                           + (2 * sizeof(unsigned int)));
      unsigned int *total =
          (unsigned int *)(packet + (ipHeader->ip_hl << 2) + ICMP_HEADER_SIZE
                           + (3 * sizeof(unsigned int)));

      // valider le nombre de fragments et le total
      if (*num >= *total)
      {
        printf("Invalid fragment number: CID=%u, TID=%u, Fragment=%u, "
               "Total=%u\n",
               *cid, *tid, *num, *total);
        continue;
      }

      // calculer la taille du payload
      unsigned int payloadSize =
          bytesRead - (ICMP_HEADER_SIZE + (4 * sizeof(unsigned int)));

      // récupére la data du payload
      unsigned char *payload =
          (unsigned char *)(packet + (ipHeader->ip_hl << 2) + ICMP_HEADER_SIZE
                            + (4 * sizeof(unsigned int)));

      // update totalChunksExpected si c'est nécessaire
      if (totalChunksExpected == -1)
      {
        totalChunksExpected = *total;
        fileChunks =
            (unsigned char *)malloc(totalChunksExpected * PAYLOAD_SIZE);
        chunkReceived = (int *)calloc(totalChunksExpected, sizeof(int));
        if (fileChunks == NULL || chunkReceived == NULL)
        {
          perror("Memory allocation failed");
          close(sockfd);
          if (outputFile != NULL)
          {
            fclose(outputFile);
          }
          free(fileChunks);
          free(chunkReceived);
          return 1;
        }
      }

      // vérifie si le fragment a déjà été reçu
      if (chunkReceived[*num] == 0)
      {
        memcpy(fileChunks + (*num * PAYLOAD_SIZE), payload, payloadSize);
        chunkReceived[*num] = 1;
        totalChunksReceived++;
        printf("Received chunk %d of %d\n", *num + 1, totalChunksExpected);
      }

      //écrit les fragement dans un fichier si ils ont tous été recus
      if (totalChunksReceived == totalChunksExpected)
      {
        char timestamp[20];
        getTimestamp(timestamp, sizeof(timestamp));

        // crée un répertoire au nom du CID reçu
        char foldername[50];
        snprintf(foldername, sizeof(foldername), "%u", *cid);

        if (mkdir(foldername, 0777) == -1)
        {
          if (errno != EEXIST)
          {
            perror("Folder creation failed");
            close(sockfd);
            free(fileChunks);
            free(chunkReceived);
            return 1;
          }
        }

        // crée le fichier timestamp
        char filename[100];
        snprintf(filename, sizeof(filename), "%s/output_file_%s_%u_%u",
                 foldername, timestamp, *cid, *tid);
        outputFile = fopen(filename, "wb");
        if (outputFile == NULL)
        {
          perror("File open failed");
          close(sockfd);
          free(fileChunks);
          free(chunkReceived);
          return 1;
        }

        // ecrire les fragments dans le fichier
        fwrite(fileChunks, 1, totalChunksExpected * PAYLOAD_SIZE, outputFile);

        printf("File received successfully\n");
        fclose(outputFile);

        // on referme le socket
        close(sockfd);
        free(fileChunks);
        free(chunkReceived);
        return 0;
      }
    }
  }
}
