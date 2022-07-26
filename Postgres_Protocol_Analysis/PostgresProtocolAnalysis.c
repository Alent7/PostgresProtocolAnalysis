#define _CRT_SECURE_NO_WARNINGS
#include "PostgresProtocolAnalysis.h"




int get_pcap_file_hdr(FILE* fp, pcap_file_hdr** pcapFileHeader)
{
	*pcapFileHeader = (pcap_file_hdr*)malloc(24);
	int n = 0;
	n = fread(*pcapFileHeader, 24, 1, fp);
	return n;
}

int get_pcap_pack_hdr(FILE* fp, pcap_pack_hdr** pcapPackHeader, char* str)
{
	*pcapPackHeader = (pcap_pack_hdr*)malloc(16);
	int n = 0;
	n = fread(*pcapPackHeader, 16, 1, fp);
	if (n <= 0)
	{
		if (feof(fp))
		{
			printf("Read complete��\n");
			return 0;
		}
		else
		{
			printf("fread faild!\n");
			return -1;
		}
	}
	else
	{
		sprintf(str, "Caplen: %d\n", (*pcapPackHeader)->Caplen);

		return n;
	}
}

int get_eth_hdr(FILE* fp, eth_hdr** ethHeader, char* str)
{
	*ethHeader = (eth_hdr*)malloc(14);
	int n = 0;
	n = fread(*ethHeader, 14, 1, fp);
	sprintf(str, "Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n", (*ethHeader)->srcmac[0], (*ethHeader)->srcmac[1], (*ethHeader)->srcmac[2], (*ethHeader)->srcmac[3], (*ethHeader)->srcmac[4], (*ethHeader)->srcmac[5], (*ethHeader)->dstmac[0], (*ethHeader)->dstmac[1], (*ethHeader)->dstmac[2], (*ethHeader)->dstmac[3], (*ethHeader)->dstmac[4], (*ethHeader)->dstmac[5]);

	return n;
}

int get_ip_hdr(FILE* fp, ip_hdr** ipHeader, char* str)
{
	*ipHeader = (ip_hdr*)malloc(20);
	int n = 0;
	n = fread(*ipHeader, 20, 1, fp);
	char strType[100];
	if ((*ipHeader)->protocol > 7)
	{
		strcpy(strType, "IP/UNKNWN");
	}
	else
	{
		strcpy(strType, Proto[(*ipHeader)->protocol]);
	}
	sprintf(str, "Source IP : %d.%d.%d.%d==>Dest   IP : %d.%d.%d.%d\nProtocol : %s\n", (*ipHeader)->srcaddr[0], (*ipHeader)->srcaddr[1], (*ipHeader)->srcaddr[2], (*ipHeader)->srcaddr[3], (*ipHeader)->dstaddr[0], (*ipHeader)->dstaddr[1], (*ipHeader)->dstaddr[2], (*ipHeader)->dstaddr[3], strType);


	return n;

}

int get_tcp_hdr(FILE* fp, tcp_hdr** tcpHeader, char* str)
{
	*tcpHeader = (tcp_hdr*)malloc(20);
	int n = 0;
	n = fread(*tcpHeader, 1, 20, fp);
	int thl = (*tcpHeader)->thl * 4;
	if ((*tcpHeader)->flag == 24)
	{
		sprintf(str, "Source Port : %d==>Dest   Port : %d\n", htons((*tcpHeader)->src_port), htons((*tcpHeader)->dst_port));
		return thl;
	}
	else if (thl > 20)
	{
		fseek(fp, thl - 20, SEEK_CUR);
		return 0;
	}
	else
	{
		return -1;
	}

}

int get_pgsql_hdr(FILE* fp, char* str)
{
	char pgsqlQuery[2048] = "";
	int type = 0;
	int len = 0;
	fread(&type, 1, 1, fp);
	switch (type)
	{
	case 0:
		fseek(fp, -1, SEEK_CUR);
		len = 0;
		fread(&len, 4, 1, fp);
		len = ntohl(len);

		int typeNum = 0;
		fread(&typeNum, 4, 1, fp);
		typeNum = ntohl(typeNum);

		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		if (typeNum == 80877103)
		{
			printf("Type: [%d] : SSLRequest \n", typeNum);
			printf("Length: %d\n", len);
			fseek(fp, len - 8, SEEK_CUR);

			//fread(pgsqlQuery, len - 8, 1, fp);
			//sprintf(str, "Status: %s\n", pgsqlQuery);
			return len;
		}
		else if (typeNum == 196608)
		{
			printf("Type: [%d] : StartupMessage \n", typeNum);
			printf("Length: %d\n", len);
			int j = 0;
			int t = 0;
			for (size_t i = 0; i < len - 4; i++)
			{

				pgsqlQuery[j] = fgetc(fp);
				char e = fgetc(fp);
				if (pgsqlQuery[j] == 0 && e != 0 && t == 0)
				{
					char buf[128] = "";
					sprintf(buf, "Parameter name: %s\n", pgsqlQuery);
					strncat(str, buf, strlen(buf) + 1);
					memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
					fseek(fp, -1, SEEK_CUR);
					j = 0;
					t = 1;
				}
				else if (pgsqlQuery[j] == 0 && e != 0 && t == 1)
				{

					fseek(fp, -1, SEEK_CUR);
					j = 0;
					t = 0;
				}
				else if (pgsqlQuery[j] == 0 && e == 0)
				{
					char buf[128] = "";
					sprintf(buf, "Parameter value: %s\n", pgsqlQuery);
					strncat(str, buf, strlen(buf) + 1);
					memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
					break;
				}
				else
				{
					fseek(fp, -1, SEEK_CUR);
					j++;
				}
			}
			return len;
		}
		else
		{
			fseek(fp, -8, SEEK_CUR);
			return -1;
			break;
		}

	case 'C':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : CommandComplete \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);
		fread(pgsqlQuery, len - 4, 1, fp);
		sprintf(str, "Status: %s\n", pgsqlQuery);
		return len + 1;

	case 'D':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : DataRow \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);

		short fieldCountD = 0;
		fread(&fieldCountD, 2, 1, fp);
		fieldCountD = ntohs(fieldCountD);
		printf("Field count: %d\n", fieldCountD);

		for (size_t i = 0; i < fieldCountD; i++)
		{
			int columnLength = 0;
			fread(&columnLength, 4, 1, fp);
			columnLength = ntohl(columnLength);
			printf("Column length: %d\n", columnLength);

			if (columnLength > 0)
			{
				char data[1024] = "";
				fread(&data, columnLength, 1, fp);

				printf("Data: %s\n", data);
			}
		}
		return len + 1;

	case 'K':
		len = 0;

		printf("Type: [%c] : BackendKeyData  \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);

		int pid = 0;
		int key = 0;
		fread(&pid, 4, 1, fp);
		pid = ntohl(pid);
		fread(&key, 4, 1, fp);
		key = ntohl(key);
		sprintf(str, "PID: %d\nKey: %d\n", pid, key);

		return len + 1;

	case 'N':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : NoticeResponse \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);

		char responseType = '0';
		fread(&responseType, 1, 1, fp);

		if (responseType == 0)
		{
			sprintf(str, "Response type: [%d] \nString: No string follows!\n", responseType);
			return 6;
		}
		else
		{
			fread(pgsqlQuery, len - 5, 1, fp);
			sprintf(str, "Response type: [%c] \nString: %s\n", pgsqlQuery);
			return len + 1;
		}

	case 'Q':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : Query \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);
		fread(pgsqlQuery, len - 4, 1, fp);
		sprintf(str, "Query: \n%s\n", pgsqlQuery);
		return len + 1;

	case 'R':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		fread(&len, 4, 1, fp);
		len = ntohl(len);

		int autNum = 0;
		fread(&autNum, 4, 1, fp);
		autNum = ntohl(autNum);

		switch (autNum)
		{
		case 0:
			printf("Type: [%c] : AuthenticationOk \n", type);
			printf("Length: %d\n", len);

			sprintf(str, "Authentication type: Success(%d)\n", autNum);
			return len + 1;
		case 5:
			printf("Type: [%c] : AuthenticationMD5Password \n", type);
			printf("Length: %d\n", len);
			fread(pgsqlQuery, len - 8, 1, fp);
			sprintf(str, "Authentication type: MD5 passwprd(%d)\nSalt value: %d-%d%d%d", autNum, pgsqlQuery[0], pgsqlQuery[1], pgsqlQuery[2], pgsqlQuery[3]);
			return len + 1;
		default:
			printf("Type: [%c] : Authentication request \n", type);
			printf("Length: %d\n", len);
			//fread(str, len - 4, 1, fp);
			fseek(fp, len - 4, SEEK_CUR);
			return len + 1;
		}

	case 'S':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : Sync \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);
		int j = 0;
		int t = 0;
		for (size_t i = 0; i < len - 4; i++)
		{
			pgsqlQuery[j] = fgetc(fp);
			j++;
			if (pgsqlQuery[j - 1] == 0)
			{

				if (t == 0)
				{
					sprintf(str, "Parameter name: %s\n", pgsqlQuery);
					j = 0;
				}
				else
				{
					char buf[128] = "";
					sprintf(buf, "Parameter value: %s\n", pgsqlQuery);
					strncat(str, buf, strlen(buf) + 1);
				}
				memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
				t = 1;
			}
		}
		return len + 1;

	case 'T':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : RowDescription  \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);

		short fieldCountT = 0;
		fread(&fieldCountT, 2, 1, fp);
		fieldCountT = ntohs(fieldCountT);
		printf("Field count: %d\n", fieldCountT);

		for (size_t i = 0; i < fieldCountT; i++)
		{
			int i = 0;
			char columnName[128] = "";
			while (1)
			{
				columnName[i] = fgetc(fp);
				if (columnName[i] == 0)
				{
					break;
				}
				i++;
			}
			printf("Column name: %s\n", columnName);

			int tableOID = 0;
			fread(&tableOID, 4, 1, fp);
			tableOID = ntohl(tableOID);
			printf("Table OID: %d\n", tableOID);

			short columnIndex = 0;
			fread(&columnIndex, 2, 1, fp);
			columnIndex = ntohs(columnIndex);
			printf("Column index: %d\n", columnIndex);

			int typeOID = 0;
			fread(&typeOID, 4, 1, fp);
			typeOID = ntohl(typeOID);
			printf("Type OID: %d\n", typeOID);

			short columnLength = 0;
			fread(&columnLength, 2, 1, fp);
			columnLength = ntohs(columnLength);
			printf("Column length: %d\n", columnLength);

			int typeModifier = 0;
			fread(&typeModifier, 4, 1, fp);
			typeModifier = ntohl(typeModifier);
			printf("Type modifier: %d\n", typeModifier);

			short format = 0;
			fread(&format, 2, 1, fp);
			format = ntohs(format);
			printf("Format: Text (%d)\n", format);
		}
		return len + 1;

	case 'Z':
		len = 0;
		printf("Type: [%c] : ReadyForQuery \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);
		char b = '0';
		fread(&b, 1, 1, fp);

		if (b == 'I')
		{
			sprintf(str, "Status: Idle(%d)\n", b);
		}
		else
		{
			sprintf(str, "Status: reject(%d)\n", b);
		}

		return len + 1;

	case 'p':
		len = 0;
		memset(pgsqlQuery, 0, sizeof(pgsqlQuery));
		printf("Type: [%c] : PasswordMessage \n", type);
		fread(&len, 4, 1, fp);
		len = ntohl(len);
		printf("Length: %d\n", len);
		fread(pgsqlQuery, len - 4, 1, fp);
		sprintf(str, "Status: %s\n", pgsqlQuery);
		return len + 1;

	default:
		fseek(fp, -1, SEEK_CUR);
		return -1;
		break;
	}
}

int pcap_unpack(FILE* fp)
{
	int packNum = 0;
	int pcapPackLen = 0;
	int excessLength = 0;
	int n = 0;

	pcap_file_hdr* pcapFileHeader = NULL;


	pcapPackLen = get_pcap_file_hdr(fp, &pcapFileHeader);

	while (pcapPackLen)
	{
		pcap_pack_hdr* pcapPackHeader = NULL;
		eth_hdr* ethHeader = NULL;
		ip_hdr* ipHeader = NULL;
		tcp_hdr* tcpHeader = NULL;


		char pcapPackInfo[256] = "";
		pcapPackLen = get_pcap_pack_hdr(fp, &pcapPackHeader, &pcapPackInfo);
		excessLength = pcapPackHeader->Caplen;
		if (pcapPackLen == 0)
		{
			printf("\n！！！！！！！！！！！！！！\n\n");
			return 0;
		}

		char ehtInfo[256] = "";
		get_eth_hdr(fp, &ethHeader, &ehtInfo);
		excessLength -= 14;

		char ipInfo[256] = "";
		int ipRet = get_ip_hdr(fp, &ipHeader, &ipInfo);
		excessLength -= 20;

		char tcpInfo[256] = "";
		int n = 0;
		n = get_tcp_hdr(fp, &tcpHeader, &tcpInfo);
		excessLength -= (tcpHeader->thl) * 4;

		printf("No.%d\n", ++packNum);
		printf("%s", pcapPackInfo);
		printf("%s", ehtInfo);
		printf("%s", ipInfo);
		printf("%s", tcpInfo);

		if (n <= 0)
		{
			printf("\n！！！！！！！！！！！！！！\n\n");
			if (n < 0 && excessLength > 0)
			{
				fseek(fp, excessLength, SEEK_CUR);
				excessLength -= excessLength;
			}
		}
		else if (n > 0)
		{

			char pgsqlQuery[2048] = "";
			for (int i = 0; excessLength > 0; i++)
			{
				printf("\nStatement : %d\n", i + 1);
				int pgsql_len = get_pgsql_hdr(fp, &pgsqlQuery);


				if (pgsql_len < 0)
				{
					printf("Unrecognized statement type��\n");
					fseek(fp, excessLength, SEEK_CUR);
					excessLength -= excessLength;
				}
				else
				{
					if (pgsqlQuery)
					{
						printf("%s\n", pgsqlQuery);
					}
					excessLength -= pgsql_len;
				}
				//printf("\nexcessLength: %d\n\n", excessLength);


			}
			printf("\n！！！！！！！！！！！！！！\n\n");

		}
		free(pcapPackHeader);
		free(ethHeader);
		free(ipHeader);
		free(tcpHeader);



		pcapPackHeader = NULL;
		ethHeader = NULL;
		ipHeader = NULL;
		tcpHeader = NULL;
		if (packNum % 200 == 0)
		{
			printf("！ Press [C] to continue�　�\n");
			printf("\n！！！！！！！！！！！！！！\n\n");
			while (1)
			{
				char p = '0';
				p = getch();
				if (p == 'c' || p == 'C')
				{
					break;
				}
			}
		}

	}


	free(pcapFileHeader);
	pcapFileHeader = NULL;
}


int	main()
{

	FILE* fp;
	fp = fopen("postgresql.pcap", "rb");
	if (NULL == fp)
	{
		printf("File open failed!/n");
		return 1;
	}

	pcap_unpack(fp);

	system("pause");
	return 0;
}

