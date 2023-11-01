#include<iostream>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<pcap.h>

using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")

void packet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // ������̫��ͷ��
    const u_char* eth_header = packet;
    //�������ֽڵ�ֵ�ϲ�Ϊһ��16λ������
    unsigned short eth_type = (eth_header[12] << 8) | eth_header[13];

    printf("Դ MAC ��ַ: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header[6], eth_header[7], eth_header[8], eth_header[9], eth_header[10], eth_header[11]);
    printf("Ŀ�� MAC ��ַ: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header[0], eth_header[1], eth_header[2], eth_header[3], eth_header[4], eth_header[5]);
    printf("����: 0x%04X\n", eth_type);
    printf("���ݰ��ĳ���: %d\n", pkthdr->len);
    printf("\n");

}


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

    // ��ʼ�������ݰ�
    int result;
    struct pcap_pkthdr *header;
    const u_char* packet;

    while ((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) {
            continue; // û�����ݰ���������ȴ�
        }

        // ����������ݰ�
        packet_handler(header, packet);
    }

    if (result == -1) {
        cerr << "Error reading the packet: " << pcap_geterr(handle) << endl;
    }

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);
    // �رղ����
    pcap_close(handle);
    system("pasue");
    return 0;
}

