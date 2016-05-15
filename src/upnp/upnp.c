#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

#define MAX_NAME 128

static int reverse_dns(char *ip, char *name, int len) {
	struct hostent *hent;
	struct in_addr addr;

	if (!inet_aton(ip, &addr))
		return 0;

	if ((hent = gethostbyaddr((char *) &(addr.s_addr), sizeof(addr.s_addr),
			AF_INET))) {
		strncpy(name, hent->h_name, len);
	}

	return 1;
}

static void print_ip(char * controlURL, char *servicetype) {
	char wan_address[64];
	UPNP_GetExternalIPAddress(controlURL, servicetype, wan_address);
	printf("%s\n", wan_address);

	char name[MAX_NAME] = { 0 };
	reverse_dns(wan_address, name, sizeof(name));
	printf("%s\n", name);

	//publish(wan_address, name);
}

int main(void) {

	int error = 0;
	//struct UPNPDev *upnp_dev = upnpDiscover(50, NULL, NULL, 0, 0, 2, &error);
	struct UPNPDev *upnp_dev = upnpDiscoverAll(50, NULL, NULL, 0, 0, 2, &error);

	if(UPNPDISCOVER_SUCCESS != error){
		printf("disconver error：%d\n", error);
	}else {
		struct UPNPDev *item = upnp_dev;
		while(item){
			char lan_address[64];
			struct UPNPUrls upnp_urls;
			struct IGDdatas upnp_data;
			int status = UPNP_GetValidIGD(upnp_dev, &upnp_urls, &upnp_data, lan_address,
					sizeof(lan_address));
			if (status != 1){
				printf("Get Valid IGD failure status %d descURL:%s\n"
					, status
					, item->descURL);
			}else {

				print_ip(upnp_urls.controlURL, upnp_data.first.servicetype);
				print_ip(upnp_urls.controlURL, upnp_data.second.servicetype);

				unsigned int down = 0, up = 0;
				UPNP_GetLinkLayerMaxBitRates(upnp_urls.controlURL,
						upnp_data.first.servicetype, &down, &up);
				printf("down: %d up: %d\n", down, up);

				char type[64] = { 0 };
				UPNP_GetConnectionTypeInfo(upnp_urls.controlURL,
						upnp_data.first.servicetype, type);
				printf("%s\n", type);

				FreeUPNPUrls(&upnp_urls);
			}
			item = item->pNext;
		}
	}





	freeUPNPDevlist(upnp_dev);
}
