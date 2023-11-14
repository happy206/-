#include<iostream>
#include<time.h>
#include <string>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<pcap.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")
// ����4996����
#pragma warning(disable : 4996)


// �ֽڶ��뷽ʽ
#pragma pack(1)
// ֡�ײ�
typedef struct FrameHeader_t {
	// Ŀ�ĵ�ַ
	BYTE DesMAC[6];
	// Դ��ַ
	BYTE SrcMAC[6];
	// ֡����
	WORD FrameType;
}FrameHeader_t;
// ARP֡
typedef struct ARPFrame_t {
	// ֡�ײ�
	FrameHeader_t FrameHeader;
	// Ӳ������
	WORD HardwareType;
	// Э�����ͣ�����ʵ��Ӧ��ΪARP��
	WORD ProtocolType;
	// Ӳ����ַ����
	BYTE HLen;
	// Э���ַ����
	BYTE PLen;
	// �������ͣ�����ARP�������Ӧ��
	WORD Operation;
	// ���ͷ�MAC��ַ(ԴMAC��ַ)
	BYTE SendHa[6];
	// ���ͷ�IP��ַ(ԴIP��ַ)
	DWORD SendIP;
	// ���շ�MAC��ַ(Ŀ��MAC��ַ)
	BYTE RecvHa[6];
	// ���շ�IP��ַ(Ŀ��IP��ַ)
	DWORD RecvIP;
}ARPFrame_t;
// �����ֽڶ��뷽ʽ
# pragma pack()


int main() {

	char errbuf[PCAP_ERRBUF_SIZE];  //���ڴ洢������Ϣ
	pcap_if_t* alldevs;     //pcap_if_t ���ڱ�ʾ�����豸����Ϣ
	pcap_if_t* dev;
	// ��ȡ���õ������豸�б�
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		cerr << "Error in pcap_findalldevs: " << errbuf << endl;
		return 1;
	}

	// �����豸�б���ӡ�豸��Ϣ
	int i = 1;
	for (dev = alldevs; dev; dev = dev->next) {
		//��ӡ����ӿ�����
		cout << "Device " << i++ << ": " << dev->name << endl;
		//��ӡ����ӿ�����
		if (dev->description) {
			cout << "   Description: " << dev->description << endl;
		}
		else {
			cout << "   Description: None" << endl;
		}
		// ��ӡ����ӿڵ�IP��ַ
		pcap_addr_t* address;
		for (address = dev->addresses; address != NULL; address = address->next)
		{
			switch (address->addr->sa_family)
			{
				// IPV4���͵�ַ
			case AF_INET:
				cout << "��ַ����ΪIPv4 ";
				if (address->addr != NULL)
				{
					// ��ӡIP��ַ
					cout << "IP��ַ:  " << inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr) << endl;
				}
				break;
				// IPV6���͵�ַ
			case AF_INET6:
				cout << "��ַ����ΪIPV6" << endl;
				break;
			default:
				break;
			}
		}
		cout << endl;
	}
	// ������ӿ�
	pcap_t* handle = NULL;
	int number;
	cout << "������Ҫ�򿪵�����ӿں�: " << endl;
	cin >> number;
	i = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		i++;
		if (i == number) {
			// ������ӿ��Խ������ݰ�����
			handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
			break;
		}
	}
	if (handle == NULL) {
		cerr << "Error opening network interface: " << errbuf << endl;
		return 1;
	}

	char* IP = new char[40];
	// ���豸��IP��ַ��ֵ��IP����
	strcpy(IP, inet_ntoa(((struct sockaddr_in*)(dev->addresses)->addr)->sin_addr));

	/*----����ARP֡�����ݣ�����ȡ������MAC��ַ��IP��ַ�Ĺ�ϵ-----*/

	// ARP��ʼ֡
	ARPFrame_t ARPFrame;
    //����Ŀ�ĵ�ַΪ�㲥��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}

	// ����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x55;
	}

	// ֡����ΪARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// Ӳ������Ϊ��̫��
	ARPFrame.HardwareType = htons(0x0001);
	// Э������ΪIP
	ARPFrame.ProtocolType = htons(0x0800);
	// Ӳ����ַ����Ϊ6
	ARPFrame.HLen = 6;
	// Э���ַ��Ϊ4
	ARPFrame.PLen = 4;
	// ����ΪARP����
	ARPFrame.Operation = htons(0x0001);
    // ����Ϊ����������MAC��ַ������ʵ��
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x55;
	}
	// ����Ϊ���������ϰ󶨵�IP��ַ������ʵ��
	ARPFrame.SendIP = inet_addr("110.110.110.110");
	// ����Ŀ��MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}
	// ����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(IP);

	// �������úõ�֡���ݣ��������ʧ��ֱ���˳�
	if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "����ʧ��" << endl;
		return -1;
	}
	cout << "���ͳɹ�" << endl;

	// �������������ARP֡
	ARPFrame_t* ARPPacket;

	// ��ʼ�������ݱ�
	while (true)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int result = pcap_next_ex(handle, &pkt_header, &pkt_data);
		// ������Ӧ����Ϣ
		if (result == 1)
		{
			ARPPacket = (ARPFrame_t*)pkt_data;
			if ((ntohs(ARPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(ARPPacket->Operation) == 0x0002))
				//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				// ��ӡ������MAC��ַ��IP��ַ
				cout << "IP��ַ: " << IP << endl;
				/*printf("%s\t%s\n", "IP��ַ:", IP);*/
				cout << "MAC��ַ: ";
				/*printf("Mac��ַ��\n");*/
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					ARPPacket->FrameHeader.SrcMAC[0],
					ARPPacket->FrameHeader.SrcMAC[1],
					ARPPacket->FrameHeader.SrcMAC[2],
					ARPPacket->FrameHeader.SrcMAC[3],
					ARPPacket->FrameHeader.SrcMAC[4],
					ARPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}

	/*-----����Ŀ��IP��ַ�������Ŀ��IP��ַ��MAC��ַ�Ĺ�ϵ����ֻ����ͬһ��������------*/
	

	// Ŀ��IP��ַ
	char* DestIP = new char[40];

	cout << "���������뷢�͵���Ŀ��IP��ַ:" << endl;
	cin >> DestIP;

	 //�л����������ӿڵ�����
     for (int i = 0; i < 6; i++){
	 	 ARPFrame.FrameHeader.SrcMAC[i] = ARPPacket->FrameHeader.SrcMAC[i];
	 	 ARPFrame.SendHa[i] = ARPPacket->FrameHeader.SrcMAC[i];
	 }
	 ARPFrame.SendIP = ARPPacket->SendIP;
	// ����Ŀ��IP��ַ
	ARPFrame.RecvIP = inet_addr(DestIP);
	// �������úõ�֡���ݣ��������ʧ��ֱ���˳�
	if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "����ʧ��" << endl;
		return -1;
	}
	else
	{
		cout << "���ͳɹ�" << endl;
	}
	ARPFrame_t* NewARPPacket;

	//��ʼ�������ݱ�
	while (true)
	{
		pcap_pkthdr* pkt_headerNew;
		const u_char* pkt_dataNew;
		int result = pcap_next_ex(handle, &pkt_headerNew, &pkt_dataNew);
		if (result == 1)
		{
			NewARPPacket = (ARPFrame_t*)pkt_dataNew;
			if ((ntohs(NewARPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(NewARPPacket->Operation) == 0x0002))
				//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				// ������Ӧ��MAC��ַ
				printf("Mac��ַ��\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					NewARPPacket->FrameHeader.SrcMAC[0],
					NewARPPacket->FrameHeader.SrcMAC[1],
					NewARPPacket->FrameHeader.SrcMAC[2],
					NewARPPacket->FrameHeader.SrcMAC[3],
					NewARPPacket->FrameHeader.SrcMAC[4],
					NewARPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	delete[]DestIP;
	delete[]IP;
	// �ͷ��豸�б�
	pcap_freealldevs(alldevs);
	// �رղ����
	pcap_close(handle);
	system("pause");
	return 0;
}