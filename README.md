# PostgresProtocolAnalysis
PostgreSQL数据库协议解析

这是一个对PostgreSQL数据库进行协议解析的程序

postgresql.pcap为利用Wireshark工具抓包生成的原始数据包文件

程序每次对200条数据包进行分析，按C键继续

分析结果：

No.200	

Caplen: 476 ----------------------------------------------------------(数据包长度)

Source MAC : 40-8D-5C-94-02-E7==>Dest   MAC : 1C-1B-0D-9C-07-E5 ------(源端mac地址==>目的mac地址)

Source IP : 192.168.20.6==>Dest   IP : 192.168.16.128 ----------------(源端ip==>目的ip)

Protocol : TCP -------------------------------------------------------(协议类型)

Source Port : 54543==>Dest   Port : 5432 -----------------------------(源端口==>目的端口)

Statement : 1 --------------------------------------------------------(语句个数)
Type: [Q] : Query ----------------------------------------------------(SQL动作：查询)

Length: 421 ----------------------------------------------------------(SQL语句长度/字节)

Query: ---------------------------------------------------------------(SQL语句)	
SELECT ...

	
