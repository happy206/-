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
//本机的MAC地址
BYTE OwnMac[6];
//本机的IP地址和掩码
char OwnIP_1[20] = "";
char OwnIP_2[20] = "";
char OwnMASK[20] = "";
// 字节对齐方式
#pragma pack(1)
// 帧首部结构体
typedef struct FrameHeader_t {
	// 目的地址
	BYTE DesMAC[6];
	// 源地址
	BYTE SrcMAC[6];
	// 帧类型
	WORD FrameType;
}FrameHeader_t;
// ARP报文结构体
typedef struct ARPFrame_t {
	// 帧首部
	FrameHeader_t FrameHeader;
	// 硬件类型
	WORD HardwareType;
	// 协议类型
	WORD ProtocolType;
	// 硬件地址长度
	BYTE HLen;
	// 协议地址长度
	BYTE PLen;
	// 操作类型
	WORD Operation;
	// 发送方MAC地址(源MAC地址)
	BYTE SendMac[6];
	// 发送方IP地址(源IP地址)
	DWORD SendIP;
	// 接收方MAC地址(目的MAC地址)
	BYTE RecvMac[6];
	// 接收方IP地址(目的IP地址)
	DWORD RecvIP;
}ARPFrame_t;
// IP报文头部结构体
typedef struct IPHeader_t
{
	BYTE Ver_HLen;          // 版本和首部长度（Version and Header Length）
	BYTE TOS;               // 服务类型（Type of Service）
	WORD TotalLen;          // 总长度（Total Length）
	WORD ID;                // 标识（Identification）
	WORD Flag_Segment;      // 标志和片偏移（Flags and Fragment Offset）
	BYTE TTL;               // 存活时间（Time to Live）
	BYTE Protocol;          // 协议类型（Protocol）
	WORD Checksum;          // 校验和（Header Checksum）
	ULONG SrcIP;            // 源IP地址（Source IP Address）
	ULONG DstIP;            // 目的IP地址（Destination IP Address）
} IPHeader_t;
// ICMP报文头部结构体
typedef struct ICMPHeader_t {
	BYTE Type; // 类型
	BYTE Code; // 代码
	WORD Checksum; // 校验和
	WORD Id; // 标识
	WORD Sequence; // 序列号
} ICMPHeader_t;
// ICMP报文
typedef struct ICMP {
	// 帧首部
	FrameHeader_t FrameHeader;
	// IP首部
	IPHeader_t IPHeader;
	//ICMP首部
	ICMPHeader_t ICMPHeader;
	//数据部分
	char buf[0x80];
}ICMP_t;
// 结束字节对齐方式
# pragma pack()

// 字节对齐方式
#pragma pack(1)
// 路由表项
class RouteItem {
public:
	// 掩码
	DWORD mask;
	// 目的网络
	DWORD dstnet;
	// 下一跳的IP地址
	DWORD nextIP;
	// 下一跳的MAC地址
	BYTE nextMAC[6];
	// 序号
	int number;
	// 类型0为直接相连,即直接投递的; 1为用户添加（直接相连 不可删除）
	int type;
	//指向下一个路由表项得指针
	RouteItem* NextItem;
	RouteItem() {
		// 将其全部设置为零
		memset(this, 0, sizeof(*this));
	}
	// 打印掩码、目的网络、下一跳IP、类型
	void printitem() {
		// 打印的内容为：子网掩码、目的网络、下一跳IP和类型
		in_addr addr;
		cout << "路由表项" << left << setw(2) << number << ":  ";

		addr.s_addr = mask;
		cout << "子网掩码为:  " << left << setw(17) << inet_ntoa(addr);


		addr.s_addr = dstnet;
		cout << "目的网络为:  " << left << setw(17) << inet_ntoa(addr);

		addr.s_addr = nextIP;
		cout << "下一跳IP地址为:  " << left << setw(17) << inet_ntoa(addr);

		if (type == 0) {
			cout << "类型为:   直接相连" << endl;
		}
		else {
			cout << "类型为:   用户添加" << endl;
		}
	}
};
#pragma pack()

#pragma pack(1)
// 路由表
class RouteTable
{
public:
	//head和tail都是边界，不是具体的路由表项
	RouteItem* head, * tail;
	// 目前存在的个数
	int num;
	// 路由表采用链表形式 并初始化直接跳转的网络
	RouteTable() {
		head = new RouteItem;
		tail = new RouteItem;
		head->NextItem = tail;
		tail->NextItem = NULL;
		num = 0;
	}
	//初始化函数
	void initialize() {
		// 本次实验初始一定只有两个网络
		if (strcmp(OwnIP_1, "") != 0) {
			RouteItem* temp = new RouteItem;
			// 本机网卡的IP和掩码进行按位与的结果为网络号
			temp->dstnet = (inet_addr(OwnIP_1)) & (inet_addr(OwnMASK));
			temp->mask = inet_addr(OwnMASK);
			temp->type = 0;
			// 将其初始化到链表中
			this->add(temp);
		}
		if (strcmp(OwnIP_2, "") != 0) {
			RouteItem* temp = new RouteItem;
			// 本机网卡的IP和掩码进行按位与的结果为网络号
			temp->dstnet = (inet_addr(OwnIP_2)) & (inet_addr(OwnMASK));
			temp->mask = inet_addr(OwnMASK);
			temp->type = 0;
			// 将其初始化到链表中
			this->add(temp);
		}
	}
	// 添加路由表项(不是直接投递的表项在直接投递的表项后面)
	void add(RouteItem* a) {
		RouteItem* temp = new RouteItem(*a);
		//按照掩码由长至短找到合适的位置
		if (num == 0) {
			temp->NextItem = head->NextItem;
			head->NextItem = temp;
		}
		else {
			// 方便找到插入的位置
			RouteItem* pointer;
			for (pointer = head->NextItem; pointer->NextItem != tail; pointer = pointer->NextItem){

				if (temp->mask < pointer->mask && temp->mask >= pointer->NextItem->mask) {
					break;
				}
			}
			// 插入到合适位置
			temp->NextItem = pointer->NextItem;
			pointer->NextItem = temp;
		}
		//设置编号
		RouteItem* pointer = head->NextItem;
		for (int i = 0; pointer != tail; pointer = pointer->NextItem, i++)
		{
			pointer->number = i;
		}
		num++;
	}
	//删除路由表项
	void remove(int number) {
		for (RouteItem* t = head; t->NextItem != tail; t = t->NextItem) {

			if (t->NextItem->number == number) {
				// 直接投递的路由表项(type=0)不可删除
				if (t->NextItem->type == 0) {
					cout << "该项无法删除" << endl;
					return;
				}
				else {
					t->NextItem = t->NextItem->NextItem;
					cout << "删除成功!" << endl;
					return;
				}
			}
		}
		cout << "查无此项！" << endl;
	}
	//打印路由表:即打印（掩码、网络号、下一跳IP地址）
	void print() {
		RouteItem* pointer = head->NextItem;
		for (; pointer != tail; pointer = pointer->NextItem)
		{
			pointer->printitem();
		}
	}
	//查找 （最长前缀 返回下一跳的`ip`地址）
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
#pragma pack()//恢复4bytes对齐

//日志类
class RouteLog {
public:
	// 索引
	int index;
	// 值为“ARP”或“IP”
	char type[5];
	//日志文件
	FILE* text_file;
	//行数
	int line;
	//初始化日志
	RouteLog() {
		// 初始化日志的参数
		line = 0;
		//以追加（"a"）和读取（"+"）的模式
		text_file = fopen("Log.txt", "a+");
	}
	// 将ARP响应得到的IP与MAC地址映射写入日志文件
	void write_ARPLog(ARPFrame_t* pkt) {
		fprintf(text_file, "ARP:");
		in_addr addr;
		addr.s_addr = pkt->SendIP;
		fprintf(text_file, "IP： ");
		fprintf(text_file, "%s  ", inet_ntoa(addr));

		fprintf(text_file, "MAC： ");
		for (int i = 0; i < 5; i++) {
			fprintf(text_file, "%02X-", pkt->SendMac[i]);
		}
		fprintf(text_file, "%02X\n", pkt->SendMac[5]);
	}
	//将转发过程和接收过程写入日志（op代表转发或接收）
	void write_route(const char* op, ICMP_t* pkt) {
		fprintf(text_file, "`IP`");
		fprintf(text_file, op);
		fprintf(text_file, ": ");
		in_addr addr;
		addr.s_addr = pkt->IPHeader.SrcIP;
		char* pchar = inet_ntoa(addr);
		fprintf(text_file, "源IP： ");
		fprintf(text_file, "%s  ", pchar);
		fprintf(text_file, "目的IP： ");
		addr.s_addr = pkt->IPHeader.DstIP;
		fprintf(text_file, "%s\n", pchar);
	}
	// 日志打印
	void print() {
		// 读取文件内容并输出到标准输出
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
//ARP表项
class ARPItem {
public:
	// IP地址
	DWORD IP;
	// MAC地址
	BYTE MAC[6];
};
// ARP缓存表(存储已经得到的IP与MAC的映射关系)
class ARPtable {
public:
	static ARPItem arpitem[50];
	// 表项数量
	static int num;
	// 插入表项(自带发送ARP请求)
	static void insert(DWORD ip, BYTE mac[6], pcap_t*& handle, RouteLog& WorkLog) {
		arpitem[num].IP = ip;
		getOtherDeviceMAC(ip, arpitem[num].MAC, handle, WorkLog);
		memcpy(mac, arpitem[num].MAC, 6);
		num++;
	}
	// 查找表项
	static int lookup(DWORD ip, BYTE mac[6]) {
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++) {
			if (ip == arpitem[i].IP) {
				memcpy(mac, arpitem[i].MAC, 6);
				return 1;
			}
		}
		// 没找到则返回0
		return 0;
	}
};
ARPItem ARPtable::arpitem[50] = {};
// 初始化ARP表项数量
int ARPtable::num = 0;

// 对比两个MAC地址是否相同,相同返回1,不同返回0
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
// 获取目的`IP`和`MAC`地址
void getOtherDeviceMAC(DWORD ip, BYTE mac[], pcap_t*& handle, RouteLog& WorkLog) {
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;

	// 将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}

	// 将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.SrcMAC[i] = OwnMac[i];
		ARPFrame.SendMac[i] = OwnMac[i];
	}

	// 帧类型为ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// 硬件类型为以太网
	ARPFrame.HardwareType = htons(0x0001);
	// 协议类型为IP
	ARPFrame.ProtocolType = htons(0x0800);
	// 硬件地址长度为6
	ARPFrame.HLen = 6;
	// 协议地址长为4
	ARPFrame.PLen = 4;
	// 操作为ARP请求
	ARPFrame.Operation = htons(0x0001);

	// 将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(OwnIP_1);

	// 将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++) {
		ARPFrame.RecvMac[i] = 0;
	}

	// 将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);

	if (handle == NULL) {
		cout << "网卡接口打开失败" << endl;
	}
	else {
		if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) {
			cout << "发送失败" << endl;
		}
		else {
			while (true)
			{
				cout << "向外部发送ARP请求成功！" << endl;
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
				if (rtn == 1){
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806) {
						// 检查是否为 ARP 响应
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip) {
							// 把获得的关系写入到日志表中
							WorkLog.write_ARPLog(IPPacket);
							// 写入源MAC地址
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