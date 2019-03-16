
#if(defined WIN32) || (defined WIN64)  

#include "windows.h"
#include <Iphlpapi.h>
#include "stdlib.h"
#include "stdio.h"
#pragma comment(lib,"Iphlpapi.lib")  


int getMacAddress(char *mac_addr) {

	BYTE  ind = 0;
	mac_addr[0] = 0;

	ULONG ulAdapterInfoSize(0);
	GetAdaptersInfo(NULL, &ulAdapterInfoSize);
	if (ulAdapterInfoSize)
	{
		IP_ADAPTER_INFO*pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
		IP_ADAPTER_INFO*pAdapterInfoBkp = pAdapterInfo;
		IP_ADDR_STRING* pIPAddr = NULL;
		if (GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) == ERROR_SUCCESS)
		{
			do  //遍历所有适配器  
			{
				if (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET ||
					pAdapterInfo->Type == IF_TYPE_IEEE80211)//判断是否为以太网接口  
				{
					int mac_len = 0;
					for (DWORD i = 0; i < pAdapterInfo->AddressLength; i++)
					{
						mac_len += 3;
						sprintf(mac_addr + i * 3, "%02X-", pAdapterInfo->Address[i]);
					}
					if (mac_len > 0) {
						mac_len = mac_len - 1;
						mac_addr[mac_len] = '\0';
					}

					if (strlen(pAdapterInfo->GatewayList.IpAddress.String) > 0 && strlen(pAdapterInfo->GatewayList.IpAddress.String) >0 &&
						strcmp(pAdapterInfo->GatewayList.IpAddress.String, "0.0.0.0") != 0 && strcmp(pAdapterInfo->GatewayList.IpAddress.String, "0.0.0.0") != 0)
					{
						break;
					}
				}
				ind++;
				pAdapterInfo = pAdapterInfo->Next;
			} while (pAdapterInfo);
		}
		delete pAdapterInfoBkp;
	}

	return ind;
}

#else


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>


#define IFRSIZE ((int)(size*sizeof(struct ifreq)))  
/*
int getMacAddress(char *mac) {
struct ifreq ifreq;
int sock = 0;


sock = socket(AF_INET, SOCK_STREAM, 0);
if (sock < 0)
{
perror("error sock");
return 2;
}

int device_success = 0;
char* net_name[] = { "eth0","eno1", "ens4f0" };

for (int i = 0; i < sizeof(net_name) / sizeof(char*); i++)
{
strcpy(ifreq.ifr_name, net_name[i]);
if (ioctl(sock, SIOCGIFHWADDR, &ifreq) == 0)
{
device_success = 1;
break;
}
}

if (!device_success)
{
perror("error ioctl23");
return 3;
}


int i = 0;
for (i = 0; i < 6; i++) {
sprintf(mac + 3 * i, "%02X:", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
}
mac[strlen(mac) - 1] = 0;

return 0;
}

*/


//获取本机网卡地址 
int getMacAddress(char *mac_addr)
{
	mac_addr[0] = 0;

	char null_card[6] = { 0 };
	int ind = 0;
	int  sockfd, size = 1;
	struct ifconf ifc;
	struct sockaddr_in sa;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))<0) return(0);
	ifc.ifc_req = NULL;
	do
	{
		++size;
		if (!(ifc.ifc_req = (ifreq*)realloc(ifc.ifc_req, IFRSIZE))) return(0);
		ifc.ifc_len = IFRSIZE;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc)) return(0);
	} while (IFRSIZE <= ifc.ifc_len);

	struct ifreq *ifr = ifc.ifc_req;

	for (; (char*)ifr<(char*)ifc.ifc_req + ifc.ifc_len; ++ifr)
	{
		if (ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data) continue;
		if (ioctl(sockfd, SIOCGIFFLAGS, ifr)) continue;
		if (!ioctl(sockfd, SIOCGIFHWADDR, ifr))
		{
			switch (ifr->ifr_hwaddr.sa_family)
			{
			case ARPHRD_NETROM:
			case ARPHRD_ETHER:
			case ARPHRD_PPP:
			case ARPHRD_EETHER:
			case ARPHRD_IEEE802:
				break;
			default:
				continue;
			}
			if (memcmp(ifr->ifr_addr.sa_data, null_card, 6))
			{

				int mac_len = 0;
				for (int i = 0; i < 6; i++)
				{
					mac_len += 3;
					sprintf(mac_addr + i * 3, "%02X-", (unsigned char)ifr->ifr_hwaddr.sa_data[i]);
				}
				if (mac_len > 0) {
					mac_len = mac_len - 1;
					mac_addr[mac_len] = '\0';
				}

				if (strcmp(ifr->ifr_ifrn.ifrn_name, "eth0") == 0 || strcmp(ifr->ifr_ifrn.ifrn_name, "eno1") == 0 || strcmp(ifr->ifr_ifrn.ifrn_name, "ens4f0") == 0 || strcmp(ifr->ifr_ifrn.ifrn_name, "bond0") == 0)
				{
					break;
				}
				ind++;
			}
		}
	}
	close(sockfd);
	return ind;
}

#endif  
