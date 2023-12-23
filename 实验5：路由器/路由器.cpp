//忽略警告
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
// 忽略4996错误
#pragma warning(disable : 4996)
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")

// 宏定义
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10
//路由器工作日志
RouteLog WorkLog;
//广播地址
BYTE broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
// 获取网络设备
void find_alldevs(char* pcap_src_if_string, pcap_t*& handle) {

	char errbuf[PCAP_ERRBUF_SIZE];  //用于存储错误信息
	pcap_if_t* alldevs;             //pcap_if_t 用于表示网络设备的信息
	pcap_if_t* dev;
	// 获取可用的网络设备列表
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1) {
		cout << "无法获取本机设备" << endl;
		// 释放设备列表
		pcap_freealldevs(alldevs);
	}
	else {
		//遍历设备列表并打印设备信息
		int i = 0;
		int num = 0;
		for (dev = alldevs; dev; dev = dev->next) {
			// 设备数加1
			num++;
			//打印网络接口名字
			cout << "Device " << i + 1 << ": " << dev->name << endl;
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
						// 打印IP地址和掩码
						cout << "IP地址:  " << inet_ntoa(((struct sockaddr_in*)address->addr)->sin_addr) << endl;
						cout << "子网掩码：" << inet_ntoa(((struct sockaddr_in*)address->netmask)->sin_addr) << endl;
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
			i++;
		}
		// 没有接口直接返回
		if (num == 0) {
			cout << "没有接口" << endl;
			return;
		}
		// 用户选择接口
		cout << "请选择你想打开的接口：" << "`1 ~ " << num << "`:" << endl;
		int number;
		i = 0;
		cin >> number;
		// 跳转到相应接口
		for (dev = alldevs; dev; dev = dev->next) {
			i++;
			if (i == number) {
				// 打开网络接口以进行数据包捕获
				//IP数据报的最大长度可达65535个字节
				handle = pcap_open(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
				pcap_addr_t* address = dev->addresses;
				//存储打开的网卡的IP和子网掩码
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
// 打印MAC地址
void printMAC(BYTE MAC[]) {
	for (int i = 0; i < 5; i++) {
		printf("%02X-", MAC[i]);
	}
	printf("%02X\n", MAC[5]);
}
// 计算 IP 头部校验和
void setchecksum_IP(IPHeader_t* temp)
{
	// 将原始校验和字段置为 0
	temp->Checksum = 0;

	// 初始化变量，用于存储校验和的中间结果
	unsigned int sum = 0;

	// 定义指针，指向数据结构 temp 中的 IP 首部
	WORD* t = (WORD*)temp;

	// 遍历 IP 首部的每两个字节
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		// 将每两个字节的值相加到 sum 中
		sum += t[i];

		// 包含原有的校验和相加
		// 如果 sum 超过 16 位，则将溢出的部分加回到 sum 中
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// 对 sum 取反，然后赋值给 IP 头部的校验和字段
	temp->Checksum = ~sum;
}

// 检查 IP 头部校验和
bool checkchecksum_IP(IPHeader_t* temp)
{
	// 初始化变量，用于存储校验和的中间结果
	unsigned int sum = 0;

	// 定义指针，指向数据结构 temp 中的 IP 首部
	WORD* t = (WORD*)temp;

	// 遍历 IP 首部的每两个字节
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		// 将每两个字节的值相加到 sum 中
		sum += t[i];

		// 包含原有的校验和相加
		// 如果 sum 超过 16 位，则将溢出的部分加回到 sum 中
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// 检查校验和是否等于 65535
	if (sum == 65535)
	{
		// 校验和全1代表正确，返回 true
		return true;
	}

	// 校验和不等于 65535，代表错误，返回 false
	return false;
}
// 数据报转发(修改源MAC和目的MAC)
void resend(ICMP_t data, BYTE DstMAC[], pcap_t*& handle,int packetLength) {
	ICMP_t* temp = &data;
	// 将源MAC改为本机MAC
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);
	// 将目的MAC改为下一跳MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);
	// 发送数据报
	int rtn = pcap_sendpacket(handle, (const u_char*)temp, packetLength);
	//int rtn = pcap_sendpacket(handle, (const u_char*)temp, 74);
	if (rtn == 0) {
		// 将其写入日志
		WorkLog.write_route("转发", temp);
	}
}
// 发送ICMP超时报文(修改源MAC和目的MAC)
void send(ICMP_t data, BYTE DstMAC[], pcap_t*& handle) {
	ICMP_t* temp = &data;
	// 将源MAC改为本机MAC
	memcpy(temp->FrameHeader.SrcMAC, OwnMac, 6);
	// 将目的MAC改为下一跳MAC
	memcpy(temp->FrameHeader.DesMAC, DstMAC, 6);
	// 发送数据报
	int rtn = pcap_sendpacket(handle, (const u_char*)temp, 70);
	if (rtn == 0) {
		// 将其写入日志
		WorkLog.write_route("发送", temp);
	}
}
// 转发线程函数
void Routeforward(RouteTable routetable, pcap_t*& handle) {
	while (true) {
		// 定义一个指向pcap_pkthdr结构的指针，用于存储数据包的头部信息
		pcap_pkthdr* pkt_header;
		// 定义一个指向u_char类型的指针，用于存储数据包的数据部分
		const u_char* pkt_data;
		// 无限循环，直到接收到数据包
		while (true) {
			// 使用pcap_next_ex函数从handle指定的数据源获取下一个数据包
			// 如果成功接收到数据包，pcap_next_ex函数会返回1，并且pkt_header和pkt_data会被设置为指向数据包的头部信息和数据部分
			int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
			// 如果接收到数据包，就跳出循环
			if (rtn) {
				break;
			}
		}
		int packetLength = pkt_header->caplen;
		// 将接收到的数据包的数据部分转换为ICMP_t类型的数据
		ICMP_t* data = (ICMP_t*)pkt_data;
		//比较数据包的目标MAC地址（data->FrameHeader.DesMAC）和本机的MAC地址（OwnMac）
		if (compare(data->FrameHeader.DesMAC, OwnMac)) {
			// 检查数据包的帧类型是否为0x0800（即IP协议）
			// ntohs函数用于将网络字节序转化为主机字节序
			if (ntohs(data->FrameHeader.FrameType) == 0x0800) {
				//检查IP数据报的上层协议是否为ICMP（Protocol字段是一个字节的，不存在字节序的问题）
				if (data->IPHeader.Protocol == 1) {
					// 如果是，将接收到的数据包写入日志
					WorkLog.write_route("接收", data);
					// 获取数据包的源IP地址和目标IP地址
					DWORD SourceIP = data->IPHeader.SrcIP;
					DWORD DestIP = data->IPHeader.DstIP;
					// 在路由表中查找目标IP地址对应的下一跳IP地址
					DWORD NextIP = routetable.lookup(DestIP);
					// 如果在路由表中没有找到对应的表项，就丢弃这个数据包，并输出一条消息
					if (NextIP == -1) {
						cout << "未找到转发路径，已丢弃该数据包！" << endl;
						continue;
					}
					// 首先，检查IP报头的校验和是否正确
					// 如果校验和不正确，则直接丢弃数据包，不进行后续处理
					if (checkchecksum_IP(&data->IPHeader)) {
						// 检查数据包的目标IP地址是否为本机的IP地址
						// 如果不是本机的IP地址，那么这个数据包需要转发
						if (data->IPHeader.DstIP != inet_addr(OwnIP_1) && data->IPHeader.DstIP != inet_addr(OwnIP_2)) {
							// 检查数据包是否为广播消息
							// 如果不是广播消息，那么需要对数据包进行转发
							int t1 = compare(data->FrameHeader.DesMAC, broadcast);
							int t2 = compare(data->FrameHeader.SrcMAC, broadcast);
							if (!t1 && !t2) {
								// 如果TTL字段减1后的值为0，那么需要发送一个ICMP超时消息
								if (data->IPHeader.TTL-1 == 0) {
									//构造ICMP超时报文
									ICMP_t* icmp_packet = new ICMP_t(*data);
									//清空
									memset(icmp_packet, 0, sizeof(ICMP_t));
									//设置帧头部
									icmp_packet->FrameHeader.FrameType = htons(0x0800);
									//设置IP头部
									icmp_packet->IPHeader.Ver_HLen = 0b01000101;
									icmp_packet->IPHeader.TOS = 0;
									icmp_packet->IPHeader.TotalLen = htons(56);
									icmp_packet->IPHeader.Flag_Segment = htons(0);
									icmp_packet->IPHeader.ID = 0;
									icmp_packet->IPHeader.TTL = 128;    //生存时间
									icmp_packet->IPHeader.Protocol = 1; // ICMP的协议号
									icmp_packet->IPHeader.SrcIP = inet_addr(OwnIP_2);
									icmp_packet->IPHeader.DstIP = data->IPHeader.SrcIP;
									//计算校验和
									setchecksum_IP(&icmp_packet->IPHeader);
									// 设置ICMP类型和代码
									icmp_packet->ICMPHeader.Type = 11; // ICMP超时类型
									icmp_packet->ICMPHeader.Code = 0; // 超时的代码
									icmp_packet->ICMPHeader.Checksum = htons(0xf4ff);
									//将接收到的IP数据包的IP头部和数据部分的前64bit(就是ICMP头部)放到数据部分
									memcpy(icmp_packet->buf, &data->IPHeader, sizeof(data->IPHeader));
									memcpy(icmp_packet->buf + sizeof(data->IPHeader), &data->ICMPHeader, sizeof(data->ICMPHeader));
									//获取源IP和目的IP
									SourceIP = icmp_packet->IPHeader.SrcIP;
									DestIP = icmp_packet->IPHeader.DstIP;
									//查找路由表，找相关的路径
									NextIP = routetable.lookup(DestIP);
									//如果找到了
									if (NextIP != -1) {
										//用于存储获取到的MAC地址
										BYTE mac[6];
										if (NextIP == 0) {
											//发送ARP请求，寻找下一跳的MAC地址
											if (!ARPtable::lookup(DestIP, mac)) {
												//insert()函数中会发送ARP请求
												ARPtable::insert(DestIP, mac, handle, WorkLog);
											}
											// 发送超时ICMP报文
											send(*icmp_packet, mac, handle);

										}
										else {
											//发送ARP请求，寻找下一跳的MAC地址
											if (!ARPtable::lookup(NextIP, mac)) {
												ARPtable::insert(NextIP, mac, handle, WorkLog);
											}
											//计算IP头部校验和
											setchecksum_IP(&icmp_packet->IPHeader);
											// 发送超时ICMP报文
											send(*icmp_packet, mac, handle);
										}
										// 打印的内容为：`源IP 目的IP 下一跳IP`
										in_addr addr;
										cout << "---------------------------------------------------------------------------------------" << endl;
										cout << "发送超时ICMP报文ing" << endl;
										cout << "源IP： ";
										addr.s_addr = SourceIP;
										char* pchar = inet_ntoa(addr);
										printf("%s\t", pchar);
										cout << endl;

										cout << "目的IP： ";
										addr.s_addr = DestIP;
										pchar = inet_ntoa(addr);
										printf("%s\t", pchar);
										cout << endl;

										cout << "下一跳IP： ";
										addr.s_addr = NextIP;
										pchar = inet_ntoa(addr);
										printf("%s\t\t", pchar);
										cout << endl;

										cout << "---------------------------------------------------------------------------------------" << endl;
									}
								}
								else {
									// 将数据包的TTL字段减1
									data->IPHeader.TTL -= 1;
									//重新计算IP头部校验和
									setchecksum_IP(&data->IPHeader);
									//用于存储获取到的MAC地址
									BYTE mac[6];
									// 如果下一跳IP地址为0，那么这是一个直接投递的数据包
									if (NextIP == 0) {
										//获取MAC地址
										if (!ARPtable::lookup(DestIP, mac)) {
											//insert()函数中会发送ARP请求
											ARPtable::insert(DestIP, mac, handle, WorkLog);
										}
										// 转发数据包
										resend(*data, mac, handle, packetLength);
									}
									// 如果下一跳IP地址不为-1和0，那么这是一个非直接投递的数据包
									else if (NextIP != -1) {
										if (!ARPtable::lookup(NextIP, mac)) {
											ARPtable::insert(NextIP, mac, handle, WorkLog);
										}
										// 转发数据包
										resend(*data, mac, handle, packetLength);
									}
									// 打印的内容为：`源IP 目的IP 下一跳IP`
									in_addr addr;
									cout << "---------------------------------------------------------------------------------------" << endl;
									cout << "转发数据报ing" << endl;
									cout << "源IP： ";
									addr.s_addr = SourceIP;
									char* pchar = inet_ntoa(addr);
									printf("%s\t", pchar);
									cout << endl;

									cout << "目的IP： ";
									addr.s_addr = DestIP;
									pchar = inet_ntoa(addr);
									printf("%s\t", pchar);
									cout << endl;

									cout << "下一跳IP： ";
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
						cout << "校验和不正确，已丢弃该数据包" << endl;
					}

				}
			}
		}
	}
}
// 根据IP获得本机的MAC地址
void getOwnMac(DWORD IP, pcap_t*& handle) {
	// 初始化 OwnMac 数组为 0
	memset(OwnMac, 0, sizeof(OwnMac));
	// 创建 ARP 帧结构体
	ARPFrame_t ARPFrame;
	// 设置 ARP 帧的目的地址为广播地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	// 设置 ARP 帧的源 MAC 地址为虚拟 MAC 地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
	}
	// 设置 ARP 帧的帧类型为 ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// 设置 ARP 帧的硬件类型为以太网
	ARPFrame.HardwareType = htons(0x0001);
	// 设置 ARP 帧的协议类型为 IP
	ARPFrame.ProtocolType = htons(0x0800);
	// 设置 ARP 帧的硬件地址长度为 6
	ARPFrame.HLen = 6;
	// 设置 ARP 帧的协议地址长度为 4
	ARPFrame.PLen = 4;
	// 设置 ARP 帧的操作为 ARP 请求
	ARPFrame.Operation = htons(0x0001);
	// 设置 ARP 帧的发送方硬件地址为虚拟 MAC 地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.SendMac[i] = 0x66;
	}
	// 设置 ARP 帧的发送方 IP 地址为虚拟 IP 地址
	ARPFrame.SendIP = inet_addr("112.112.112.112");
	// 设置 ARP 帧的接收方硬件地址为未知的 MAC 地址
	for (int i = 0; i < 6; i++) {
		ARPFrame.RecvMac[i] = 0x00;
	}
	// 设置 ARP 帧的接收方 IP 地址为传入的 IP 地址
	ARPFrame.RecvIP = IP;

	// 检查句柄是否为NULL
	if (handle == NULL) {
		cout << "网卡接口打开错误" << endl;
	}
	else {
		bool success = true;
		while (success) {
			// 发送 ARP 帧
			pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
			if (true) {
				ARPFrame_t* IPPacket;

				// 循环接收并处理 ARP 响应帧
				while (true) {
					pcap_pkthdr* pkt_header;
					const u_char* pkt_data;

					// 获取下一个数据包
					int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);

					// 如果成功获取数据包
					if (rtn == 1) {
						// 将数据包的内容解析为 ARP 帧
						IPPacket = (ARPFrame_t*)pkt_data;

						// 检查帧类型是否为 ARP
						if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) {
							// 检查是否为 ARP 响应
							if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)) {
								// 把获得的关系写入到日志表中
								WorkLog.write_ARPLog(IPPacket);

								// 将源 MAC 地址复制到 OwnMac 中
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
	//将const char* PCAP_SRC_IF_STRING 变为 char* pcap_src_if_string（接口字符串）
	// 解决使用函数pcap_findalldevs_ex()报错的问题
	char* pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);
	//打开的网络接口
	pcap_t* handle = NULL;
	// 获取网络设备
	find_alldevs(pcap_src_if_string, handle);
	//获取本机MAC地址
	cout << "本机MAC地址为： ";
	getOwnMac(inet_addr(OwnIP_1), handle);
	printMAC(OwnMac);
	//路由表
	RouteTable routetable;
	//初始化路由表
	routetable.initialize();
	//启动接收线程
	thread RouteforwardThread(Routeforward, routetable, ref(handle));
	RouteforwardThread.detach();
	int operation;
	while (true)
	{
		// 进行简介
		cout << "====================================================================================" << endl;
		cout << "欢迎来到高级路由器，请选择你想要进行的操作：" << endl;
		cout << "1. 添加路由表项" << endl;
		cout << "2. 删除路由表项" << endl;
		cout << "3. 打印路由表：" << endl;
		cout << "4. 退出程序" << endl;
		cout << "====================================================================================" << endl;
		// 输入想要进行的操作
		cin >> operation;
		if (operation == 1)
		{
			RouteItem routeitem;
			char cin_mask[30];
			char cin_dstip[30];
			char cin_nextip[30];
			cout << "请输入网络掩码：" << endl;
			cin >> cin_mask;
			routeitem.mask = inet_addr(cin_mask);

			cout << "请输入目的网络`ip`地址：" << endl;
			cin >> cin_dstip;
			routeitem.dstnet = inet_addr(cin_dstip);

			cout << "请输入下一跳`ip`地址：" << endl;
			cin >> cin_nextip;
			routeitem.nextIP = inet_addr(cin_nextip);

			// 手动添加的类型
			routeitem.type = 1;
			routetable.add(&routeitem);
		}
		else if (operation == 2)
		{
			cout << "请输入你想要删除的表项编号：" << endl;
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
			cout << "请输入正确的操作号！" << endl;
		}
	}
	return 0;
}