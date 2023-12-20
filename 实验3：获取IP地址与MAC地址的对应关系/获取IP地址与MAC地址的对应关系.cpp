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
// 忽略4996错误
#pragma warning(disable : 4996)


// 字节对齐方式
#pragma pack(1)
// 帧首部
typedef struct FrameHeader_t {
	// 目的地址
	BYTE DesMAC[6];
	// 源地址
	BYTE SrcMAC[6];
	// 帧类型
	WORD FrameType;
}FrameHeader_t;
// ARP帧
typedef struct ARPFrame_t {
	// 帧首部
	FrameHeader_t FrameHeader;
	// 硬件类型
	WORD HardwareType;
	// 协议类型（本次实验应该为ARP）
	WORD ProtocolType;
	// 硬件地址长度
	BYTE HLen;
	// 协议地址长度
	BYTE PLen;
	// 操作类型（比如ARP的请求或应答）
	WORD Operation;
	// 发送方MAC地址(源MAC地址)
	BYTE SendHa[6];
	// 发送方IP地址(源IP地址)
	DWORD SendIP;
	// 接收方MAC地址(目的MAC地址)
	BYTE RecvHa[6];
	// 接收方IP地址(目的IP地址)
	DWORD RecvIP;
}ARPFrame_t;
// 结束字节对齐方式
# pragma pack()


int main() {

	char errbuf[PCAP_ERRBUF_SIZE];  //用于存储错误信息
	pcap_if_t* alldevs;     //pcap_if_t 用于表示网络设备的信息
	pcap_if_t* dev;
	// 获取可用的网络设备列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		cerr << "Error in pcap_findalldevs: " << errbuf << endl;
		return 1;
	}

	// 遍历设备列表并打印设备信息
	int i = 1;
	for (dev = alldevs; dev; dev = dev->next) {
		//打印网络接口名字
		cout << "Device " << i++ << ": " << dev->name << endl;
		//打印网络接口描述
		if (dev->description) {
			cout << "   Description: " << dev->description << endl;
		}
		else {
			cout << "   Description: None" << endl;
		}
		// 打印网络接口的IP地址
		pcap_addr_t* address;
		for (address = dev->addresses; address != NULL; address = address->next)
		{
			switch (address->addr->sa_family)
			{
				// IPV4类型地址
			case AF_INET:
				cout << "地址类型为IPv4 ";
				if (address->addr != NULL)
				{
					// 打印IP地址
					cout << "IP地址:  " << inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr) << endl;
				}
				break;
				// IPV6类型地址
			case AF_INET6:
				cout << "地址类型为IPV6" << endl;
				break;
			default:
				break;
			}
		}
		cout << endl;
	}
	// 打开网络接口
	pcap_t* handle = NULL;
	int number;
	cout << "请输入要打开的网络接口号: " << endl;
	cin >> number;
	i = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		i++;
		if (i == number) {
			// 打开网络接口以进行数据包捕获
			handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
			break;
		}
	}
	if (handle == NULL) {
		cerr << "Error opening network interface: " << errbuf << endl;
		return 1;
	}

	char* IP = new char[40];
	// 将设备的IP地址赋值给IP数组
	strcpy(IP, inet_ntoa(((struct sockaddr_in*)(dev->addresses)->addr)->sin_addr));

	/*----设置ARP帧的内容，并获取本机的MAC地址与IP地址的关系-----*/

	// ARP初始帧
	ARPFrame_t ARPFrame;
    //设置目的地址为广播地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}

	// 设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x55;
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
    // 设置为本机网卡的MAC地址（非真实）
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x55;
	}
	// 设置为本机网卡上绑定的IP地址（非真实）
	ARPFrame.SendIP = inet_addr("110.110.110.110");
	// 设置目的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}
	// 设置为请求的IP地址
	ARPFrame.RecvIP = inet_addr(IP);

	// 发送设置好的帧内容，如果发送失败直接退出
	if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "发送失败" << endl;
		return -1;
	}
	cout << "发送成功" << endl;

	// 声明即将捕获的ARP帧
	ARPFrame_t* ARPPacket;

	// 开始捕获数据报
	while (true)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int result = pcap_next_ex(handle, &pkt_header, &pkt_data);
		// 捕获到相应的信息
		if (result == 1)
		{
			ARPPacket = (ARPFrame_t*)pkt_data;
			if ((ntohs(ARPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(ARPPacket->Operation) == 0x0002))
				//如果帧类型为ARP并且操作为ARP应答
			{
				// 打印本机的MAC地址和IP地址
				cout << "IP地址: " << IP << endl;
				/*printf("%s\t%s\n", "IP地址:", IP);*/
				cout << "MAC地址: ";
				/*printf("Mac地址：\n");*/
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

	/*-----输入目的IP地址，来获得目的IP地址和MAC地址的关系，但只能在同一个网段中------*/
	

	// 目的IP地址
	char* DestIP = new char[40];

	cout << "请输入你想发送到的目的IP地址:" << endl;
	cin >> DestIP;

	 //切换到这个网络接口的网段
     for (int i = 0; i < 6; i++){
	 	 ARPFrame.FrameHeader.SrcMAC[i] = ARPPacket->FrameHeader.SrcMAC[i];
	 	 ARPFrame.SendHa[i] = ARPPacket->FrameHeader.SrcMAC[i];
	 }
	 ARPFrame.SendIP = ARPPacket->SendIP;
	// 设置目的IP地址
	ARPFrame.RecvIP = inet_addr(DestIP);
	// 发送设置好的帧内容，如果发送失败直接退出
	if (pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "发送失败" << endl;
		return -1;
	}
	else
	{
		cout << "发送成功" << endl;
	}
	ARPFrame_t* NewARPPacket;

	//开始捕获数据报
	while (true)
	{
		pcap_pkthdr* pkt_headerNew;
		const u_char* pkt_dataNew;
		int result = pcap_next_ex(handle, &pkt_headerNew, &pkt_dataNew);
		if (result == 1)
		{
			NewARPPacket = (ARPFrame_t*)pkt_dataNew;
			if ((ntohs(NewARPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(NewARPPacket->Operation) == 0x0002))
				//如果帧类型为ARP并且操作为ARP应答
			{
				// 输出其对应的MAC地址
				printf("Mac地址：\n");
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
	// 释放设备列表
	pcap_freealldevs(alldevs);
	// 关闭捕获点
	pcap_close(handle);
	system("pause");
	return 0;
}