//���Ծ���
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<iostream>
#include<time.h>
#include<thread>
#include <string>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<pcap.h>
#include"router.h"
using namespace std;
// ����4996����
#pragma warning(disable : 4996)
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")

// �궨��
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10
//·����������־
RouteLog WorkLog;
//�㲥��ַ
BYTE broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
// ��ȡ�����豸
void find_alldevs(char* pcap_src_if_string, pcap_t*& handle) {

	char errbuf[PCAP_ERRBUF_SIZE];  //���ڴ洢������Ϣ
	pcap_if_t* alldevs;             //pcap_if_t ���ڱ�ʾ�����豸����Ϣ
	pcap_if_t* dev;
	// ��ȡ���õ������豸�б�
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1) {
		cout << "�޷���ȡ�����豸" << endl;
		// �ͷ��豸�б�
		pcap_freealldevs(alldevs);
	}
	else {
		//�����豸�б���ӡ�豸��Ϣ
		int i = 0;
		int num = 0;
		for (dev = alldevs; dev; dev = dev->next) {
			// �豸����1
			num++;
			//��ӡ����ӿ�����
			cout << "Device " << i + 1 << ": " << dev->name << endl;
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
						// ��ӡIP��ַ������
						cout << "IP��ַ:  " << inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr) << endl;
						cout << "�������룺" << inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr) << endl;
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
			i++;
		}
		// û�нӿ�ֱ�ӷ���
		if (num == 0) {
			cout << "û�нӿ�" << endl;
			return;
		}
		// �û�ѡ��ӿ�
		cout << "��ѡ������򿪵Ľӿڣ�" << "`1 ~ " << num << "`:" << endl;
		int number;
		i = 0;
		cin >> number;
		// ��ת����Ӧ�ӿ�
		for (dev = alldevs; dev; dev = dev->next) {
			i++;
			if (i == number) {
				// ������ӿ��Խ������ݰ�����
				//IP���ݱ�����󳤶ȿɴ�65535���ֽ�
				handle = pcap_open(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
				pcap_addr_t* address = dev->addresses;
				//�洢�򿪵�������IP����������
				strcpy(OwnMASK, inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr));
				strcpy(OwnIP_1, inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));
				if (address->next != NULL) {
					address = address->next;
					strcpy(OwnIP_2, inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr));
				}
				break;
			}
		}
		if (handle == NULL) {
			cerr << "Error opening network interface: " << errbuf << endl;
			return;
		}
	}
	pcap_freealldevs(alldevs);
}
// ��ӡMAC��ַ
void printMAC(BYTE MAC[]) {
	for (int i = 0; i < 5; i++) {
		printf("%02X-", MAC[i]);
	}
	printf("%02X\n", MAC[5]);
}
// ���� IP ͷ��У���
void setchecksum_IP(IPHeader_t* temp)
{
	// ��ԭʼУ����ֶ���Ϊ 0
	temp->Checksum = 0;

	// ��ʼ�����������ڴ洢У��͵��м���
	unsigned int sum = 0;

	// ����ָ�룬ָ�����ݽṹ temp �е� IP �ײ�
	WORD* t = (WORD*)temp;

	// ���� IP �ײ���ÿ�����ֽ�
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		// ��ÿ�����ֽڵ�ֵ��ӵ� sum ��
		sum += t[i];

		// ����ԭ�е�У������
		// ��� sum ���� 16 λ��������Ĳ��ּӻص� sum ��
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// �� sum ȡ����Ȼ��ֵ�� IP ͷ����У����ֶ�
	temp->Checksum = ~sum;
}

// ��� IP ͷ��У���
bool checkchecksum_IP(IPHeader_t* temp)
{
	// ��ʼ�����������ڴ洢У��͵��м���
	unsigned int sum = 0;

	// ����ָ�룬ָ�����ݽṹ temp �е� IP �ײ�
	WORD* t = (WORD*)temp;

	// ���� IP �ײ���ÿ�����ֽ�
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		// ��ÿ�����ֽڵ�ֵ��ӵ� sum ��
		sum += t[i];

		// ����ԭ�е�У������
		// ��� sum ���� 16 λ��������Ĳ��ּӻص� sum ��
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// ���У����Ƿ���� 65535
	if (sum == 65535)
	{
		// У���ȫ1������ȷ������ true
		return true;
	}

	// У��Ͳ����� 65535��������󣬷��� false
	return false;
}
// ���ݱ�ת��(�޸�ԴMAC��Ŀ��MAC)
void resend(ICMP_t data, BYTE DstMAC[], pcap_t*& handle,int packetLength) {
	ICMP_t* temp = &data;
	// ��ԴMAC��Ϊ����MAC
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);
	// ��Ŀ��MAC��Ϊ��һ��MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);
	// �������ݱ�
	int rtn = pcap_sendpacket(handle, (const u_char*)temp, packetLength);
	//int rtn = pcap_sendpacket(handle, (const u_char*)temp, 74);
	if (rtn == 0) {
		// ����д����־
		WorkLog.write_route("ת��", temp);
	}
}
// ����ICMP��ʱ����(�޸�ԴMAC��Ŀ��MAC)
void send(ICMP_t data, BYTE DstMAC[], pcap_t*& handle) {
	ICMP_t* temp = &data;
	// ��ԴMAC��Ϊ����MAC
	memcpy(temp->FrameHeader.SrcMAC, OwnMac, 6);
	// ��Ŀ��MAC��Ϊ��һ��MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);
	// �������ݱ�
	int rtn = pcap_sendpacket(handle, (const u_char*)temp, 70);
	if (rtn == 0) {
		// ����д����־
		WorkLog.write_route("����", temp);
	}
}
// ת���̺߳���
void Routeforward(RouteTable routetable, pcap_t*& handle) {
	while (true) {
		// ����һ��ָ��pcap_pkthdr�ṹ��ָ�룬���ڴ洢���ݰ���ͷ����Ϣ
		pcap_pkthdr* pkt_header;
		// ����һ��ָ��u_char���͵�ָ�룬���ڴ洢���ݰ������ݲ���
		const u_char* pkt_data;
		// ����ѭ����ֱ�����յ����ݰ�
		while (true) {
			// ʹ��pcap_next_ex������handleָ��������Դ��ȡ��һ�����ݰ�
			// ����ɹ����յ����ݰ���pcap_next_ex�����᷵��1������pkt_header��pkt_data�ᱻ����Ϊָ�����ݰ���ͷ����Ϣ�����ݲ���
			int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
			// ������յ����ݰ���������ѭ��
			if (rtn) {
				break;
			}
		}
		int packetLength = pkt_header->caplen;
		// �����յ������ݰ������ݲ���ת��ΪICMP_t���͵�����
		ICMP_t* data = (ICMP_t*)pkt_data;
		//�Ƚ����ݰ���Ŀ��MAC��ַ��data->FrameHeader.DesMAC���ͱ�����MAC��ַ��OwnMac��
		if (compare(data->FrameHeader.DesMAC, OwnMac)) {
			// ������ݰ���֡�����Ƿ�Ϊ0x0800����IPЭ�飩
			// ntohs�������ڽ������ֽ���ת��Ϊ�����ֽ���
			if (ntohs(data->FrameHeader.FrameType) == 0x0800) {
				//���IP���ݱ����ϲ�Э���Ƿ�ΪICMP��Protocol�ֶ���һ���ֽڵģ��������ֽ�������⣩
				if (data->IPHeader.Protocol == 1) {
					// ����ǣ������յ������ݰ�д����־
					WorkLog.write_route("����", data);
					// ��ȡ���ݰ���ԴIP��ַ��Ŀ��IP��ַ
					DWORD SourceIP = data->IPHeader.SrcIP;
					DWORD DestIP = data->IPHeader.DstIP;
					// ��·�ɱ��в���Ŀ��IP��ַ��Ӧ����һ��IP��ַ
					DWORD NextIP = routetable.lookup(DestIP);
					// �����·�ɱ���û���ҵ���Ӧ�ı���Ͷ���������ݰ��������һ����Ϣ
					if (NextIP == -1) {
						cout << "δ�ҵ�ת��·�����Ѷ��������ݰ���" << endl;
						continue;
					}
					// ���ȣ����IP��ͷ��У����Ƿ���ȷ
					// ���У��Ͳ���ȷ����ֱ�Ӷ������ݰ��������к�������
					if (checkchecksum_IP(&data->IPHeader)) {
						// ������ݰ���Ŀ��IP��ַ�Ƿ�Ϊ������IP��ַ
						// ������Ǳ�����IP��ַ����ô������ݰ���Ҫת��
						if (data->IPHeader.DstIP != inet_addr(OwnIP_1) && data->IPHeader.DstIP != inet_addr(OwnIP_2)) {
							// ������ݰ��Ƿ�Ϊ�㲥��Ϣ
							// ������ǹ㲥��Ϣ����ô��Ҫ�����ݰ�����ת��
							int t1 = compare(data->FrameHeader.DesMAC, broadcast);
							int t2 = compare(data->FrameHeader.SrcMAC, broadcast);
							if (!t1 && !t2) {
								// ���TTL�ֶμ�1���ֵΪ0����ô��Ҫ����һ��ICMP��ʱ��Ϣ
								if (data->IPHeader.TTL-1 == 0) {
									//����ICMP��ʱ����
									ICMP_t* icmp_packet = new ICMP_t(*data);
									//���
									memset(icmp_packet, 0, sizeof(ICMP_t));
									//����֡ͷ��
									icmp_packet->FrameHeader.FrameType = htons(0x0800);
									//����IPͷ��
									icmp_packet->IPHeader.Ver_HLen = 0b01000101;
									icmp_packet->IPHeader.TOS = 0;
									icmp_packet->IPHeader.TotalLen = htons(56);
									icmp_packet->IPHeader.Flag_Segment = htons(0);
									icmp_packet->IPHeader.ID = 0;
									icmp_packet->IPHeader.TTL = 128;    //����ʱ��
									icmp_packet->IPHeader.Protocol = 1; // ICMP��Э���
									icmp_packet->IPHeader.SrcIP = inet_addr(OwnIP_2);
									icmp_packet->IPHeader.DstIP = data->IPHeader.SrcIP;
									//����У���
									setchecksum_IP(&icmp_packet->IPHeader);
									// ����ICMP���ͺʹ���
									icmp_packet->ICMPHeader.Type = 11; // ICMP��ʱ����
									icmp_packet->ICMPHeader.Code = 0; // ��ʱ�Ĵ���
									icmp_packet->ICMPHeader.Checksum = htons(0xf4ff);
									//�����յ���IP���ݰ���IPͷ�������ݲ��ֵ�ǰ64bit(����ICMPͷ��)�ŵ����ݲ���
									memcpy(icmp_packet->buf, &data->IPHeader, sizeof(data->IPHeader));
									memcpy(icmp_packet->buf + sizeof(data->IPHeader), &data->ICMPHeader, sizeof(data->ICMPHeader));
									//��ȡԴIP��Ŀ��IP
									SourceIP = icmp_packet->IPHeader.SrcIP;
									DestIP = icmp_packet->IPHeader.DstIP;
									//����·�ɱ�����ص�·��
									NextIP = routetable.lookup(DestIP);
									//����ҵ���
									if (NextIP != -1) {
										//���ڴ洢��ȡ����MAC��ַ
										BYTE mac[6];
										if (NextIP == 0) {
											//����ARP����Ѱ����һ����MAC��ַ
											if (!ARPtable::lookup(DestIP, mac)) {
												//insert()�����лᷢ��ARP����
												ARPtable::insert(DestIP, mac, handle, WorkLog);
											}
											// ���ͳ�ʱICMP����
											send(*icmp_packet, mac, handle);

										}
										else {
											//����ARP����Ѱ����һ����MAC��ַ
											if (!ARPtable::lookup(NextIP, mac)) {
												ARPtable::insert(NextIP, mac, handle, WorkLog);
											}
											//����IPͷ��У���
											setchecksum_IP(&icmp_packet->IPHeader);
											// ���ͳ�ʱICMP����
											send(*icmp_packet, mac, handle);
										}
										// ��ӡ������Ϊ��`ԴIP Ŀ��IP ��һ��IP`
										in_addr addr;
										cout << "---------------------------------------------------------------------------------------" << endl;
										cout << "���ͳ�ʱICMP����ing" << endl;
										cout << "ԴIP�� ";
										addr.s_addr = SourceIP;
										char* pchar = inet_ntoa(addr);
										printf("%s\t", pchar);
										cout << endl;

										cout << "Ŀ��IP�� ";
										addr.s_addr = DestIP;
										pchar = inet_ntoa(addr);
										printf("%s\t", pchar);
										cout << endl;

										cout << "��һ��IP�� ";
										addr.s_addr = NextIP;
										pchar = inet_ntoa(addr);
										printf("%s\t\t", pchar);
										cout << endl;

										cout << "---------------------------------------------------------------------------------------" << endl;
									}
								}
								else {
									// �����ݰ���TTL�ֶμ�1
									data->IPHeader.TTL -= 1;
									//���¼���IPͷ��У���
									setchecksum_IP(&data->IPHeader);
									//���ڴ洢��ȡ����MAC��ַ
									BYTE mac[6];
									// �����һ��IP��ַΪ0����ô����һ��ֱ��Ͷ�ݵ����ݰ�
									if (NextIP == 0) {
										//��ȡMAC��ַ
										if (!ARPtable::lookup(DestIP, mac)) {
											//insert()�����лᷢ��ARP����
											ARPtable::insert(DestIP, mac, handle, WorkLog);
										}
										// ת�����ݰ�
										resend(*data, mac, handle, packetLength);
									}
									// �����һ��IP��ַ��Ϊ-1��0����ô����һ����ֱ��Ͷ�ݵ����ݰ�
									else if (NextIP != -1) {
										if (!ARPtable::lookup(NextIP, mac)) {
											ARPtable::insert(NextIP, mac, handle, WorkLog);
										}
										// ת�����ݰ�
										resend(*data, mac, handle, packetLength);
									}
									// ��ӡ������Ϊ��`ԴIP Ŀ��IP ��һ��IP`
									in_addr addr;
									cout << "---------------------------------------------------------------------------------------" << endl;
									cout << "ת�����ݱ�ing" << endl;
									cout << "ԴIP�� ";
									addr.s_addr = SourceIP;
									char* pchar = inet_ntoa(addr);
									printf("%s\t", pchar);
									cout << endl;

									cout << "Ŀ��IP�� ";
									addr.s_addr = DestIP;
									pchar = inet_ntoa(addr);
									printf("%s\t", pchar);
									cout << endl;

									cout << "��һ��IP�� ";
									addr.s_addr = NextIP;
									pchar = inet_ntoa(addr);
									printf("%s\t\t", pchar);
									cout << endl;

									cout << "---------------------------------------------------------------------------------------" << endl;

								}
							}
						}

					}
					else {
						cout << "У��Ͳ���ȷ���Ѷ��������ݰ�" << endl;
					}

				}
			}
		}
	}
}
// ����IP��ñ�����MAC��ַ
void getOwnMac(DWORD IP, pcap_t*& handle) {
	// ��ʼ�� OwnMac ����Ϊ 0
	memset(OwnMac, 0, sizeof(OwnMac));
	// ���� ARP ֡�ṹ��
	ARPFrame_t ARPFrame;
	// ���� ARP ֡��Ŀ�ĵ�ַΪ�㲥��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	// ���� ARP ֡��Դ MAC ��ַΪ���� MAC ��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
	}
	// ���� ARP ֡��֡����Ϊ ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// ���� ARP ֡��Ӳ������Ϊ��̫��
	ARPFrame.HardwareType = htons(0x0001);
	// ���� ARP ֡��Э������Ϊ IP
	ARPFrame.ProtocolType = htons(0x0800);
	// ���� ARP ֡��Ӳ����ַ����Ϊ 6
	ARPFrame.HLen = 6;
	// ���� ARP ֡��Э���ַ����Ϊ 4
	ARPFrame.PLen = 4;
	// ���� ARP ֡�Ĳ���Ϊ ARP ����
	ARPFrame.Operation = htons(0x0001);
	// ���� ARP ֡�ķ��ͷ�Ӳ����ַΪ���� MAC ��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.SendMac[i] = 0x66;
	}
	// ���� ARP ֡�ķ��ͷ� IP ��ַΪ���� IP ��ַ
	ARPFrame.SendIP = inet_addr("112.112.112.112");
	// ���� ARP ֡�Ľ��շ�Ӳ����ַΪδ֪�� MAC ��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.RecvMac[i] = 0x00;
	}
	// ���� ARP ֡�Ľ��շ� IP ��ַΪ����� IP ��ַ
	ARPFrame.RecvIP = IP;

	// ������Ƿ�ΪNULL
	if (handle == NULL) {
		cout << "�����ӿڴ򿪴���" << endl;
	}
	else {
		bool success = true;
		while (success) {
			// ���� ARP ֡
			pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
			if (true) {
				ARPFrame_t* IPPacket;

				// ѭ�����ղ����� ARP ��Ӧ֡
				while (true) {
					pcap_pkthdr* pkt_header;
					const u_char* pkt_data;

					// ��ȡ��һ�����ݰ�
					int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);

					// ����ɹ���ȡ���ݰ�
					if (rtn == 1) {
						// �����ݰ������ݽ���Ϊ ARP ֡
						IPPacket = (ARPFrame_t*)pkt_data;

						// ���֡�����Ƿ�Ϊ ARP
						if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) {
							// ����Ƿ�Ϊ ARP ��Ӧ
							if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)) {
								// �ѻ�õĹ�ϵд�뵽��־����
								WorkLog.write_ARPLog(IPPacket);

								// ��Դ MAC ��ַ���Ƶ� OwnMac ��
								for (int i = 0; i < 6; i++) {
									OwnMac[i] = IPPacket->FrameHeader.SrcMAC[i];
								}
								success = false;
								break;
							}
						}
					}
				}
			}

		}
	}
}
int main()
{
	//��const char* PCAP_SRC_IF_STRING ��Ϊ char* pcap_src_if_string���ӿ��ַ�����
	// ���ʹ�ú���pcap_findalldevs_ex()���������
	char* pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);
	//�򿪵�����ӿ�
	pcap_t* handle = NULL;
	// ��ȡ�����豸
	find_alldevs(pcap_src_if_string, handle);
	//��ȡ����MAC��ַ
	cout << "����MAC��ַΪ�� ";
	getOwnMac(inet_addr(OwnIP_1), handle);
	printMAC(OwnMac);
	//·�ɱ�
	RouteTable routetable;
	//��ʼ��·�ɱ�
	routetable.initialize();
	//���������߳�
	thread RouteforwardThread(Routeforward, routetable, ref(handle));
	RouteforwardThread.detach();
	int operation;
	while (true)
	{
		// ���м��
		cout << "====================================================================================" << endl;
		cout << "��ӭ�����߼�·��������ѡ������Ҫ���еĲ�����" << endl;
		cout << "1. ���·�ɱ���" << endl;
		cout << "2. ɾ��·�ɱ���" << endl;
		cout << "3. ��ӡ·�ɱ�" << endl;
		cout << "4. �˳�����" << endl;
		cout << "====================================================================================" << endl;
		// ������Ҫ���еĲ���
		cin >> operation;
		if (operation == 1)
		{
			RouteItem routeitem;
			char cin_mask[30];
			char cin_dstip[30];
			char cin_nextip[30];
			cout << "�������������룺" << endl;
			cin >> cin_mask;
			routeitem.mask = inet_addr(cin_mask);

			cout << "������Ŀ������`ip`��ַ��" << endl;
			cin >> cin_dstip;
			routeitem.dstnet = inet_addr(cin_dstip);

			cout << "��������һ��`ip`��ַ��" << endl;
			cin >> cin_nextip;
			routeitem.nextIP = inet_addr(cin_nextip);

			// �ֶ���ӵ�����
			routeitem.type = 1;
			routetable.add(&routeitem);
		}
		else if (operation == 2)
		{
			cout << "����������Ҫɾ���ı����ţ�" << endl;
			int number;
			cin >> number;
			routetable.remove(number);
		}
		else if (operation == 3)
		{
			routetable.print();
		}
		else if (operation == 4)
		{
			break;
		}
		else {
			cout << "��������ȷ�Ĳ����ţ�" << endl;
		}
	}
	return 0;
}