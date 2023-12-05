// A checksum function
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
