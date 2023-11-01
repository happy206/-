#include<iostream>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<pcap.h>

using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")

void packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // 解析以太网头部
    const u_char* eth_header = packet;
    //将两个字节的值合并为一个16位的整数
    unsigned short eth_type = (eth_header[12] << 8) | eth_header[13];

    printf("源 MAC 地址: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header[6], eth_header[7], eth_header[8], eth_header[9], eth_header[10], eth_header[11]);
    printf("目标 MAC 地址: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header[0], eth_header[1], eth_header[2], eth_header[3], eth_header[4], eth_header[5]);
    printf("类型: 0x%04X\n", eth_type);
    printf("数据包的长度: %d\n", pkthdr->len);
    printf("\n");

}


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
        cout << "Device " << i++ << ": " << dev->name << endl;
        if (dev->description) {
            cout << "   Description: " << dev->description << endl;
        }
        else {
            cout << "   Description: N/A" << endl;
        }
        if (i == 10) {
           
        }
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

    // 开始捕获数据包
    int result;
    struct pcap_pkthdr *header;
    const u_char* packet;

    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) {
            continue; // 没有数据包到达，继续等待
        }

        // 处理捕获的数据包
        packet_handler(header, packet);
    }

    if (result == -1) {
        cerr << "Error reading the packet: " << pcap_geterr(handle) << endl;
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
    // 关闭捕获点
    pcap_close(handle);
    system("pasue");
    return 0;
}

