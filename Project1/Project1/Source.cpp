#pragma warning (disable : 4996)
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <list>
#include <chrono>

//ICMP MESSAGES TYPES
#define ICMP_ECHOREPLY      0
#define ICMP_DESTUNREACH    3
#define ICMP_ECHOREQUEST    8
#define ICMP_TIMEOUT       11

#define MAX_HOPS           30

#define ICMP_MIN            8  
#define DEF_PACKET_SIZE	   32
#define MAX_PACKET       1024

//заголовок сетевого уровня (IP)
typedef struct iphdr
{
	unsigned int   h_len : 4;      // Length of the header
	unsigned int   version : 4;    // Version of IP
	unsigned char  tos;            // Type of service
	unsigned short total_len;      // Total length of the packet
	unsigned short ident;          // Unique identifier
	unsigned short frag_and_flags; // Flags
	unsigned char  ttl;            // Time to live
	unsigned char  proto;          // Protocol (TCP, UDP etc)
	unsigned short checksum;       // IP checksum
	unsigned int   sourceIP;       // Source IP
	unsigned int   destIP;         // Destination IP
} IpHeader;

//заголовок ICMP
typedef struct icmphdr
{
	byte i_type;              // ICMP message type
	byte i_code;              // Sub code
	unsigned short i_cksum;		//checksum
	unsigned short i_id;        // Unique id
	unsigned short i_seq;       // Sequence number
	unsigned long timestamp;
} IcmpHeader;

int set_ttl(SOCKET s, int nTimeToLive)
{
	int isInvalidSock = setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&nTimeToLive, sizeof(int));
	if (isInvalidSock == SOCKET_ERROR)
	{
		std::cout << "setsockopt(IP_TTL) failed : " << WSAGetLastError();
		return 0;
	}
	return 1;
}


std::list<char *> IpaddrList;
/*декодируем IP пакет чтобы определить данные в ICMP пакете*/
int decode_resp(char *buf, int bytes, SOCKADDR_IN *from, int ttl, const char *mode, std::chrono::time_point<std::chrono::steady_clock> begin = std::chrono::steady_clock::now())
{
	struct hostent *lpHostent = NULL;
	struct in_addr RepliedAddress = from->sin_addr;
	IpHeader *iphdr = (IpHeader *)buf;
	unsigned short iphdrlen = iphdr->h_len * 4;
	IcmpHeader *icmphdr = (IcmpHeader*)(buf + iphdrlen);

	std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
	std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);

	switch (icmphdr->i_type)
	{
	case ICMP_ECHOREPLY: //если ответил конечный роутер
		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));
		if (WSAGetLastError() != 0) {
			if (mode == "first_packet")
				std::cout << ttl << '\t' << ms.count() << "ms \t";
			else if (mode == "second_packet")
				std::cout << ms.count() << "ms \t";
			else if (mode == "third_packet") {
				std::cout << ms.count() << "ms \t" << inet_ntoa(RepliedAddress) << '\n';
				std::cout << "\nTracing route completed. \n";
				WSACleanup();
				return 1;
			}
		}
		else {
			if (mode == "first_packet")
				std::cout << ttl << '\t' << ms.count() << "ms \t";
			else if (mode == "second_packet")
				std::cout << ms.count() << "ms \t";
			else if (mode == "third_packet") {
				std::cout << ms.count() << "ms \t" << lpHostent->h_name << '[' << inet_ntoa(RepliedAddress) << ']' << '\n';
				std::cout << "Tracing route completed. \n";
				WSACleanup();
				return 1;
			}
		}
		return 0;
		break;
	case ICMP_TIMEOUT:  //промежуточный
		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));
		if (WSAGetLastError() != 0) {
			if (mode == "first_packet")
				std::cout << ttl << '\t' << ms.count() << "ms \t";
			else if (mode == "second_packet")
				std::cout << ms.count() << "ms \t";
			else if (mode == "third_packet")
				std::cout << ms.count() << "ms \t" << inet_ntoa(RepliedAddress) << '\n';
		}
		else
			if (mode == "first_packet")
				std::cout << ttl << '\t' << ms.count() << "ms \t";
			else if (mode == "second_packet")
				std::cout << ms.count() << "ms \t";
			else if (mode == "third_packet")
				std::cout << ms.count() << "ms \t" << lpHostent->h_name << '[' << inet_ntoa(RepliedAddress) << ']' << '\n';
		IpaddrList.push_back(inet_ntoa(RepliedAddress));
		return 0;
		break;
	case ICMP_DESTUNREACH:  //если маршрутизатор недостижим
		std::cout << "Host is unreachable " << ttl << "\t" << inet_ntoa(RepliedAddress);
		return 1;
		break;
	}
	return 0;
}

unsigned short checksum(unsigned short *addr, int count)
{
	unsigned long cksum = 0;
	while (count > 1)
	{
		cksum += *addr++;
		count -= sizeof(unsigned short);
	}
	if (count)
		cksum += *(unsigned short*)addr;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

void fill_icmp_data(char * icmp_data, int datasize)
{
	IcmpHeader *icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHOREQUEST; //8
	icmp_hdr->i_code = 0;
	char *datapart = icmp_data + sizeof(IcmpHeader);
	memset(datapart, 'A', datasize - sizeof(IcmpHeader));
}

int main(int argc, char **argv)
{
	WSADATA wsd;
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		std::cout << "WSAStartup() failed:" << GetLastError();
		return -1;
	}
	SOCKET sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockRaw == INVALID_SOCKET)
	{
		std::cout << "WSASocket() failed : " << WSAGetLastError();
		ExitProcess(-1);
	}
	int timeout = 1000;
	int ret = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	if (ret == SOCKET_ERROR)
	{
		std::cout << "setsockopt(SO_RCVTIMEO) failed: " << WSAGetLastError();
		return -1;
	}
	SOCKADDR_IN Destinition, Sender;
	ZeroMemory(&Destinition, sizeof(Destinition));
	Destinition.sin_family = AF_INET;
	HOSTENT *isHostExists = gethostbyname(argv[1]);
	if (isHostExists) 
		memcpy(&(Destinition.sin_addr), isHostExists->h_addr, isHostExists->h_length);
	else
	{
		std::cout << "Unable to resolve " << argv[1];
		ExitProcess(-1);
	}
	int datasize = DEF_PACKET_SIZE;
	char *icmp_data = (char*)malloc(MAX_PACKET);
	char *recvbuf = (char*)malloc(MAX_PACKET);
	if ((!icmp_data) || (!recvbuf))
	{
		std::cout << "malloc() failed : " << GetLastError();
		return -1;
	}
	memset(icmp_data, 0, MAX_PACKET);
	fill_icmp_data(icmp_data, datasize);
	std::cout << "\nTracing route to " << argv[1] << " over a maximum of " << MAX_HOPS << " hops : \n";
	int done = 0;
	unsigned short seq_no = 0;
	for (int ttl = 1; ((ttl <= MAX_HOPS) && (!done)); ttl++)
	{	
		std::chrono::time_point<std::chrono::steady_clock> begin = std::chrono::steady_clock::now();
		set_ttl(sockRaw, ttl);
		((IcmpHeader*)icmp_data)->i_cksum = 0;
		((IcmpHeader*)icmp_data)->i_seq = seq_no++;
		((IcmpHeader*)icmp_data)->i_cksum = checksum((unsigned short*)icmp_data, datasize);

		int bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *)&Destinition, sizeof(Destinition));
		if (bwrote == SOCKET_ERROR)
		{
			std::cout << "sendto() failed: \n" << WSAGetLastError();
			return -1;
		}
		int countUnreceived = 0;
		int fromlen = sizeof(SOCKADDR_IN);
		bool isPacketReceived = true;
		ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&Sender, &fromlen);
		if (ret == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				std::cout << ttl << "\t *" << '\t';
				countUnreceived++;
				isPacketReceived = false;
			}
		}
		if (isPacketReceived) {
			const char *first_pack = "first_packet";
			done = decode_resp(recvbuf, ret, &Sender, ttl, first_pack, begin);
		}

		isPacketReceived = true;
		if (done != 1) {
			std::chrono::time_point<std::chrono::steady_clock> begin = std::chrono::steady_clock::now();
			bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *)&Destinition, sizeof(Destinition));
			if (bwrote == SOCKET_ERROR)
			{
				std::cout << "sendto() failed: \n" << WSAGetLastError();
				return -1;
			}
			fromlen = sizeof(SOCKADDR_IN);
			ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&Sender, &fromlen);
			if (ret == SOCKET_ERROR)
			{
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					std::cout << "*" << '\t';
					countUnreceived++;
					isPacketReceived = false;
				}
			}
			if (isPacketReceived) {
				const char *second_pack = "second_packet";
				done = decode_resp(recvbuf, ret, &Sender, ttl, second_pack, begin);
			}

			if (done != 1) {
				std::chrono::time_point<std::chrono::steady_clock> begin = std::chrono::steady_clock::now();
				bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *)&Destinition, sizeof(Destinition));
				if (bwrote == SOCKET_ERROR)
				{
					std::cout << "sendto() failed: \n" << WSAGetLastError();
					return -1;
				}
				fromlen = sizeof(SOCKADDR_IN);
				ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&Sender, &fromlen);
				if (ret == SOCKET_ERROR)
				{
					if (WSAGetLastError() == WSAETIMEDOUT)
					{
						countUnreceived++;
						if (countUnreceived == 3) {
							std::cout << "*" << '\t' << "Time out request. \n";
							continue;
						}
						else {
							std::cout << "*" << '\t' << IpaddrList.back() << '\n';
							IpaddrList.pop_back();
							continue;
						}
					}
				}
				//определяем, дошли ли мы до конечного маршрутизатора
				const char *third_pack = "third_packet";
				done = decode_resp(recvbuf, ret, &Sender, ttl, third_pack, begin);
			}
		}
	}
	if (sockRaw != INVALID_SOCKET)
		closesocket(sockRaw);
	free(icmp_data);
	free(recvbuf);
	WSACleanup();
	return 0;
}