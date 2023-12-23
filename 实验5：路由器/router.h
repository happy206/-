#pragma once
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<pcap.h>
#include <iomanip>
#include<iostream>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")
//������MAC��ַ
BYTE OwnMac[6];
//������IP��ַ������
char OwnIP_1[20] = "";
char OwnIP_2[20] = "";
char OwnMASK[20] = "";
// �ֽڶ��뷽ʽ
#pragma pack(1)
// ֡�ײ��ṹ��
typedef struct FrameHeader_t {
	// Ŀ�ĵ�ַ
	BYTE DesMAC[6];
	// Դ��ַ
	BYTE SrcMAC[6];
	// ֡����
	WORD FrameType;
}FrameHeader_t;
// ARP���Ľṹ��
typedef struct ARPFrame_t {
	// ֡�ײ�
	FrameHeader_t FrameHeader;
	// Ӳ������
	WORD HardwareType;
	// Э������
	WORD ProtocolType;
	// Ӳ����ַ����
	BYTE HLen;
	// Э���ַ����
	BYTE PLen;
	// ��������
	WORD Operation;
	// ���ͷ�MAC��ַ(ԴMAC��ַ)
	BYTE SendMac[6];
	// ���ͷ�IP��ַ(ԴIP��ַ)
	DWORD SendIP;
	// ���շ�MAC��ַ(Ŀ��MAC��ַ)
	BYTE RecvMac[6];
	// ���շ�IP��ַ(Ŀ��IP��ַ)
	DWORD RecvIP;
}ARPFrame_t;
// IP����ͷ���ṹ��
typedef struct IPHeader_t
{
	BYTE Ver_HLen;          // �汾���ײ����ȣ�Version and Header Length��
	BYTE TOS;               // �������ͣ�Type of Service��
	WORD TotalLen;          // �ܳ��ȣ�Total Length��
	WORD ID;                // ��ʶ��Identification��
	WORD Flag_Segment;      // ��־��Ƭƫ�ƣ�Flags and Fragment Offset��
	BYTE TTL;               // ���ʱ�䣨Time to Live��
	BYTE Protocol;          // Э�����ͣ�Protocol��
	WORD Checksum;          // У��ͣ�Header Checksum��
	ULONG SrcIP;            // ԴIP��ַ��Source IP Address��
	ULONG DstIP;            // Ŀ��IP��ַ��Destination IP Address��
} IPHeader_t;
// ICMP����ͷ���ṹ��
typedef struct ICMPHeader_t {
	BYTE Type; // ����
	BYTE Code; // ����
	WORD Checksum; // У���
	WORD Id; // ��ʶ
	WORD Sequence; // ���к�
} ICMPHeader_t;
// ICMP����
typedef struct ICMP {
	// ֡�ײ�
	FrameHeader_t FrameHeader;
	// IP�ײ�
	IPHeader_t IPHeader;
	//ICMP�ײ�
	ICMPHeader_t ICMPHeader;
	//���ݲ���
	char buf[0x80];
}ICMP_t;
// �����ֽڶ��뷽ʽ
# pragma pack()

// �ֽڶ��뷽ʽ
#pragma pack(1)
// ·�ɱ���
class RouteItem {
public:
	// ����
	DWORD mask;
	// Ŀ������
	DWORD dstnet;
	// ��һ����IP��ַ
	DWORD nextIP;
	// ��һ����MAC��ַ
	BYTE nextMAC[6];
	// ���
	int number;
	// ����0Ϊֱ������,��ֱ��Ͷ�ݵ�; 1Ϊ�û���ӣ�ֱ������ ����ɾ����
	int type;
	//ָ����һ��·�ɱ����ָ��
	RouteItem* NextItem;
	RouteItem() {
		// ����ȫ������Ϊ��
		memset(this, 0, sizeof(*this));
	}
	// ��ӡ���롢Ŀ�����硢��һ��IP������
	void printitem() {
		// ��ӡ������Ϊ���������롢Ŀ�����硢��һ��IP������
		in_addr addr;
		cout << "·�ɱ���" << left << setw(2) << number << ":  ";

		addr.s_addr = mask;
		cout << "��������Ϊ:  " << left << setw(17) << inet_ntoa(addr);


		addr.s_addr = dstnet;
		cout << "Ŀ������Ϊ:  " << left << setw(17) << inet_ntoa(addr);

		addr.s_addr = nextIP;
		cout << "��һ��IP��ַΪ:  " << left << setw(17) << inet_ntoa(addr);

		if (type == 0) {
			cout << "����Ϊ:   ֱ������" << endl;
		}
		else {
			cout << "����Ϊ:   �û����" << endl;
		}
	}
};
#pragma pack()

#pragma pack(1)
// ·�ɱ�
class RouteTable
{
public:
	//head��tail���Ǳ߽磬���Ǿ����·�ɱ���
	RouteItem* head, * tail;
	// Ŀǰ���ڵĸ���
	int num;
	// ·�ɱ����������ʽ ����ʼ��ֱ����ת������
	RouteTable() {
		head = new RouteItem;
		tail = new RouteItem;
		head->NextItem = tail;
		tail->NextItem = NULL;
		num = 0;
	}
	//��ʼ������
	void initialize() {
		// ����ʵ���ʼһ��ֻ����������
		if (strcmp(OwnIP_1, "") != 0) {
			RouteItem* temp = new RouteItem;
			// ����������IP��������а�λ��Ľ��Ϊ�����
			temp->dstnet = (inet_addr(OwnIP_1)) & (inet_addr(OwnMASK));
			temp->mask = inet_addr(OwnMASK);
			temp->type = 0;
			// �����ʼ����������
			this->add(temp);
		}
		if (strcmp(OwnIP_2, "") != 0) {
			RouteItem* temp = new RouteItem;
			// ����������IP��������а�λ��Ľ��Ϊ�����
			temp->dstnet = (inet_addr(OwnIP_2)) & (inet_addr(OwnMASK));
			temp->mask = inet_addr(OwnMASK);
			temp->type = 0;
			// �����ʼ����������
			this->add(temp);
		}
	}
	// ���·�ɱ���(����ֱ��Ͷ�ݵı�����ֱ��Ͷ�ݵı������)
	void add(RouteItem* a) {
		RouteItem* temp = new RouteItem(*a);
		//���������ɳ������ҵ����ʵ�λ��
		if (num == 0) {
			temp->NextItem = head->NextItem;
			head->NextItem = temp;
		}
		else {
			// �����ҵ������λ��
			RouteItem* pointer;
			for (pointer = head->NextItem; pointer->NextItem != tail; pointer = pointer->NextItem){

				if (temp->mask < pointer->mask && temp->mask >= pointer->NextItem->mask) {
					break;
				}
			}
			// ���뵽����λ��
			temp->NextItem = pointer->NextItem;
			pointer->NextItem = temp;
		}
		//���ñ��
		RouteItem* pointer = head->NextItem;
		for (int i = 0; pointer != tail; pointer = pointer->NextItem, i++)
		{
			pointer->number = i;
		}
		num++;
	}
	//ɾ��·�ɱ���
	void remove(int number) {
		for (RouteItem* t = head; t->NextItem != tail; t = t->NextItem) {

			if (t->NextItem->number == number) {
				// ֱ��Ͷ�ݵ�·�ɱ���(type=0)����ɾ��
				if (t->NextItem->type == 0) {
					cout << "�����޷�ɾ��" << endl;
					return;
				}
				else {
					t->NextItem = t->NextItem->NextItem;
					cout << "ɾ���ɹ�!" << endl;
					return;
				}
			}
		}
		cout << "���޴��" << endl;
	}
	//��ӡ·�ɱ�:����ӡ�����롢����š���һ��IP��ַ��
	void print() {
		RouteItem* pointer = head->NextItem;
		for (; pointer != tail; pointer = pointer->NextItem)
		{
			pointer->printitem();
		}
	}
	//���� ���ǰ׺ ������һ����`ip`��ַ��
	DWORD lookup(DWORD ip) {
		RouteItem* t = head->NextItem;
		for (; t != tail; t = t->NextItem)
		{
			if ((t->mask & ip) == t->dstnet) {
				return t->nextIP;
			}
		}
		return -1;
	}
};
#pragma pack()//�ָ�4bytes����

//��־��
class RouteLog {
public:
	// ����
	int index;
	// ֵΪ��ARP����IP��
	char type[5];
	//��־�ļ�
	FILE* text_file;
	//����
	int line;
	//��ʼ����־
	RouteLog() {
		// ��ʼ����־�Ĳ���
		line = 0;
		//��׷�ӣ�"a"���Ͷ�ȡ��"+"����ģʽ
		text_file = fopen("Log.txt", "a+");
	}
	// ��ARP��Ӧ�õ���IP��MAC��ַӳ��д����־�ļ�
	void write_ARPLog(ARPFrame_t* pkt) {
		fprintf(text_file, "ARP:");
		in_addr addr;
		addr.s_addr = pkt->SendIP;
		fprintf(text_file, "IP�� ");
		fprintf(text_file, "%s  ", inet_ntoa(addr));

		fprintf(text_file, "MAC�� ");
		for (int i = 0; i < 5; i++) {
			fprintf(text_file, "%02X-", pkt->SendMac[i]);
		}
		fprintf(text_file, "%02X\n", pkt->SendMac[5]);
	}
	//��ת�����̺ͽ��չ���д����־��op����ת������գ�
	void write_route(const char* op, ICMP_t* pkt) {
		fprintf(text_file, "`IP`");
		fprintf(text_file, op);
		fprintf(text_file, ": ");
		in_addr addr;
		addr.s_addr = pkt->IPHeader.SrcIP;
		char* pchar = inet_ntoa(addr);
		fprintf(text_file, "ԴIP�� ");
		fprintf(text_file, "%s  ", pchar);
		fprintf(text_file, "Ŀ��IP�� ");
		addr.s_addr = pkt->IPHeader.DstIP;
		fprintf(text_file, "%s\n", pchar);
	}
	// ��־��ӡ
	void print() {
		// ��ȡ�ļ����ݲ��������׼���
		int ch;
		while ((ch = fgetc(text_file)) != EOF) {
			std::cout << static_cast<char>(ch);
		}
	}
	~RouteLog() {
		fclose(text_file);
	}
};
void getOtherDeviceMAC(DWORD ip, BYTE mac[], pcap_t*& handle, RouteLog& WorkLog);
//ARP����
class ARPItem {
public:
	// IP��ַ
	DWORD IP;
	// MAC��ַ
	BYTE MAC[6];
};
// ARP�����(�洢�Ѿ��õ���IP��MAC��ӳ���ϵ)
class ARPtable {
public:
	static ARPItem arpitem[50];
	// ��������
	static int num;
	// �������(�Դ�����ARP����)
	static void insert(DWORD ip, BYTE mac[6], pcap_t*& handle, RouteLog& WorkLog) {
		arpitem[num].IP = ip;
		getOtherDeviceMAC(ip, arpitem[num].MAC, handle, WorkLog);
		memcpy(mac, arpitem[num].MAC, 6);
		num++;
	}
	// ���ұ���
	static int lookup(DWORD ip, BYTE mac[6]) {
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++) {
			if (ip == arpitem[i].IP) {
				memcpy(mac, arpitem[i].MAC, 6);
				return 1;
			}
		}
		// û�ҵ��򷵻�0
		return 0;
	}
};
ARPItem ARPtable::arpitem[50] = {};
// ��ʼ��ARP��������
int ARPtable::num = 0;

// �Ա�����MAC��ַ�Ƿ���ͬ,��ͬ����1,��ͬ����0
int compare(BYTE a[6], BYTE b[6])
{
	int result = 1;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			result = 0;
	}
	return result;
}
// ��ȡĿ��`IP`��`MAC`��ַ
void getOtherDeviceMAC(DWORD ip, BYTE mac[], pcap_t*& handle, RouteLog& WorkLog) {
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;

	// ��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}

	// ��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.SrcMAC[i] = OwnMac[i];
		ARPFrame.SendMac[i] = OwnMac[i];
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

	// ��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(OwnIP_1);

	// ��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++) {
		ARPFrame.RecvMac[i] = 0;
	}

	// ��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);

	if (handle == NULL) {
		cout << "�����ӿڴ�ʧ��" << endl;
	}
	else {
		if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) {
			cout << "����ʧ��" << endl;
		}
		else {
			while (true)
			{
				cout << "���ⲿ����ARP����ɹ���" << endl;
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806) {
						// ����Ƿ�Ϊ ARP ��Ӧ
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip) {
							// �ѻ�õĹ�ϵд�뵽��־����
							WorkLog.write_ARPLog(IPPacket);
							// д��ԴMAC��ַ
							for (int i = 0; i < 6; i++) {
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							}
							break;
						}
					}
				}
			}
		}
	}
}