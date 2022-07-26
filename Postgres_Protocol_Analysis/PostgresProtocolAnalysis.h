#pragma once
#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <sys/types.h>
#include <winsock.h> 
#pragma comment(lib,"ws2_32.lib")

//#include <pcap.h>

// pcap文件头部，总长度40字节
typedef struct _pcap_file_hdr {
	unsigned int magic : 32; //标识位
	unsigned short version_major : 16; //主版本号
	unsigned short version_minor : 16; //副版本号
	unsigned int thiszone : 32; //区域时间
	unsigned int sigfigs : 32; //精确时间戳
	unsigned int snaplen : 32; //数据包最大长度
	unsigned int linktype : 32; //链路层类型
}pcap_file_hdr;

// pcap数据包头部，总长度16字节
typedef struct _pcap_pack_hdr {
	unsigned int timestamp_second : 32; //时间戳高位，精确到seconds
	unsigned int timestamp_microseconds : 32; //时间戳低位，精确到microseconds
	unsigned int Caplen : 32; //当前数据区的长度
	unsigned int Len : 32; //离线数据长度
}pcap_pack_hdr;

// Mac头部，总长度14字节
typedef struct _eth_hdr
{
	unsigned char dstmac[6]; //目标mac地址
	unsigned char srcmac[6]; //源mac地址
	unsigned char eth_type[2]; //以太网类型
}eth_hdr;

//IP头部，总长度20字节
typedef struct _ip_hdr
{
	unsigned char ihl : 4; //首部长度
	unsigned char version : 4; //版本
	unsigned char tos : 8; //服务类型
	unsigned short tot_len : 16; //总长度
	unsigned short id : 16;  //标志
	unsigned short frag_off : 16; //分片偏移
	unsigned char ttl : 8; //生存时间
	unsigned char protocol : 8; //协议
	unsigned short chk_sum : 16; //检验和
	unsigned char srcaddr[4]; //源IP地址
	unsigned char dstaddr[4]; //目的IP地址
}ip_hdr;

//TCP头部，总长度20字节
typedef struct _tcp_hdr
{
	unsigned short src_port : 16; //源端口号
	unsigned short dst_port : 16; //目的端口号
	unsigned int seq_no; //序列号
	unsigned int ack_no; //确认号
	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char thl : 4; //tcp头部长度
	unsigned char flag : 6; //6位标志 
	unsigned char reseverd_2 : 2; //保留6位中的2位
	unsigned short wnd_size : 16; //16位窗口大小
	unsigned short chk_sum : 16; //16位TCP检验和
	unsigned short urgt_p : 16; //16为紧急指针
}tcp_hdr;


//协议类型
char* Proto[] = {
	"Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};


int get_pcap_file_hdr(FILE* fp, pcap_file_hdr** pcapFileHeader);//pcap文件头解析

int get_pcap_pack_hdr(FILE* fp, pcap_pack_hdr** pcapPackHeader, char* str);// pcap数据包头解析

int get_eth_hdr(FILE* fp, eth_hdr** ethHeader, char* str);// Mac头解析

int get_ip_hdr(FILE* fp, ip_hdr** ipHeader, char* str);//IP头解析

int get_pgsql_hdr(FILE* fp, char* str);//TCP头解析

int pcap_unpack(FILE* fp);//解包