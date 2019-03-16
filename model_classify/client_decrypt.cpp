#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>


#include <asm/types.h>

#include <openssl/md5.h>
#include <openssl/aes.h>


#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>


#include "base64.h"
#include "hard_info.h"

#define AES_BITS 128
#define MSG_LEN 128

using namespace std;

/**
int getMacAddress(char *mac) {
	struct ifreq ifreq;
	int sock = 0;


	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror("error sock");
		return 2;
	}

	int device_success = 0;
	char* net_name[] = { "eth0","eno1", "ens4f0", "enp129s0f0", "enp129s0f1", "ens1f1" ,"enp5s0" };

	for (int i = 0; i < sizeof(net_name)/sizeof(char*); i++)
	{
		strcpy(ifreq.ifr_name, net_name[i]);
		if (ioctl(sock, SIOCGIFHWADDR, &ifreq) == 0)
		{
			device_success = 1;
			break;
		}
	}

	if (!device_success)
	{
		perror("error ioctl23");
		return 3;
	}


	int i = 0;
	for (i = 0; i < 6; i++) {
		sprintf(mac + 3 * i, "%02X:", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
	}
	mac[strlen(mac) - 1] = 0;

	return 0;
}
*/

/*
��ȡӲ����Ϣ
*/
int getHardwareInfo(char *hardwareInfo)
{
	unsigned   long   s1 = 0, s2 = 0, s3 = 0, s4 = 0;
	char   sel;

	s1 = 0xBFEBFBFF;
	s2 = 0x000406F1;

	/*asm volatile
	("movl $0x01 , %%eax ; \n\t"
	"xorl %%edx , %%edx ;\n\t"
	"cpuid ;\n\t"
	"movl %%edx ,%0 ;\n\t"
	"movl %%eax ,%1 ; \n\t"
	:"=m"(s1), "=m"(s2)
	);
	printf("%08X-%08X-",s1,s2);
	asm volatile
	("movl $0x03,%%eax ;\n\t"
	"xorl %%ecx,%%ecx ;\n\t"
	"xorl %%edx,%%edx ;\n\t"
	"cpuid ;\n\t"
	"movl %%edx,%0 ;\n\t"
	"movl %%ecx,%1 ;\n\t"
	:"=m"(s3), "=m"(s4)
	);
	*/


	char cpuId[50];
	sprintf(cpuId, "%08X-%08X-%08X-%08X", s1, s2, s3, s4);
	//=============
	char macAddress[38];
	getMacAddress(macAddress);

	strcat(hardwareInfo, cpuId);
	strcat(hardwareInfo, "_");
	strcat(hardwareInfo, macAddress);

	int size = strlen(hardwareInfo);
	//printf("hardwareinfo===>%s \n",hardwareInfo);
	return size;
}





#define MAX_IF 10  

int getHHHHHHH()
{
	struct ifreq ifVec[MAX_IF];//�����������нӿ�  

	int sock = -1;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("Error:%d, cannot open RAM;\n");
	}

	// get if vector  
	struct ifconf ioIfConf;
		ioIfConf.ifc_buf = (char *)ifVec;
		ioIfConf.ifc_len = sizeof(ifVec);
	printf("Len:%d\n", ioIfConf.ifc_len);

	if (ioctl(sock, SIOCGIFCONF, &ioIfConf) < 0)//��ȡ��������ӿ���Ϣ  
	{
		printf("error\n");
		return 2;
	}
	return 1;
}












void getMd5(const char *input, int inputLen, char *out) {
	MD5_CTX ctx;
	unsigned char output[16];

	int i = 0;

	memset(output, 0, sizeof(output));
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, inputLen);
	MD5_Final(output, &ctx);

	for (i = 0; i<16; i++)
	{
		sprintf(out + i * 2, "%02X", output[i]);
	}
}


void getMd5WithSeed(const char *input, int inputLen, char *seedKey, int sLen, char *out) {
	MD5_CTX ctx;
	unsigned char output[16];

	int i = 0;

	memset(output, 0, sizeof(output));
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, inputLen);
	MD5_Update(&ctx, "_", 1);
	MD5_Update(&ctx, seedKey, sLen);

	MD5_Final(output, &ctx);

	for (i = 0; i<16; i++)
	{
		sprintf(out + i * 2, "%02X", output[i]);
	}
}


int decryptPbData(unsigned char *cipherData, int cipherDataLen, unsigned char pbKey[], unsigned char *pbContent) {

	//����
	AES_KEY aes_key;
	if (AES_set_decrypt_key(pbKey, 128, &aes_key)<0)
	{
		printf("���ý�����Կʧ��!!\n");
		return 0;
	}

	for (int ind = 0; ind < cipherDataLen / 16; ind++)
	{
		AES_ecb_encrypt(cipherData + ind * 16, pbContent + ind * 16, &aes_key, AES_DECRYPT);
	}

	return 1;
}

int transferSeedKey(char * seedKey, int len, char * resultKey)
{
	for (int i = 0; i< len; i++)
	{
		if (i % 2 == 0)
		{
			resultKey[i / 2] = seedKey[i];
		}
	}

}

/*
cipherData   ���������ܺõ��ַ���
clientSN   �û������id
seedKey ��������  pbkey�� key
outPbKey  �洢����pb��key
*/
int decryptPbKey(unsigned char *cipherData, int cipherDataLen, char *clientSN, char *seedKey, unsigned char *outPbKey) {

	char hardwareInfo[500];
	memset(hardwareInfo, 0, 500);
	int infoLen = getHardwareInfo(hardwareInfo);

	//printf("getHardwareInfo:%d\n ", hardwareInfo);

	char transSeedKey[50];
	memset(transSeedKey, 0, 50);
	int transSeedLen;//= transferSeedKey(seedKey, 50, transSeedKey);

					 //transSeedKey=seedKey;
	transSeedLen = 32;

	//����
	char orginalData[600];
	memset(orginalData, 0, 600);

	strcat(orginalData, clientSN);
	strcat(orginalData, "_");
	strcat(orginalData, hardwareInfo);
	//strcat(orginalData, "_");
	//strcat(orginalData, seedKey);

	//printf("orginalData:%s len:%d\n ", orginalData, strlen(orginalData));

	char md5Value[33];
	memset(md5Value, 0, 33);

	getMd5WithSeed(orginalData, strlen(orginalData), seedKey, 16, md5Value);

	//printf(" md5 value:%s \n", md5Value);
	//===================================

	unsigned char iv[AES_BLOCK_SIZE];//���ܵĳ�ʼ������
	memset(iv, 0, AES_BLOCK_SIZE);

	AES_KEY aes;
	if (AES_set_decrypt_key((unsigned char*)md5Value, 128, &aes) < 0)
	{
		printf("init aes key error.\n");
		return 0;
	}

	AES_cbc_encrypt((unsigned char*)cipherData, outPbKey, cipherDataLen, &aes, iv, AES_DECRYPT);


	return 1;

}

static const unsigned char hashmap[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
	0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
	0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
	0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
};


int hex2ByteArray(const char * str, unsigned char * bytes, int blen)
{
	unsigned char  pos;
	unsigned char  idx0;
	unsigned char  idx1;

	// mapping of ASCII characters to hex values

	bzero(bytes, blen);
	int str_len = strlen(str);
	for (pos = 0; ((pos < (blen * 2)) && (pos < str_len)); pos += 2)
	{
		idx0 = (unsigned char)str[pos + 0];
		idx1 = (unsigned char)str[pos + 1];
		bytes[pos / 2] = (unsigned char)((hashmap[idx0] << 4) | hashmap[idx1]);
	};

	return(0);
}


int inner_setupLicense()
{
	char clientSN[200];
	printf("please input you client sn:");
	scanf("%s", clientSN);

	char seedKeyHex[] = "8874e9f4a5eec793873c56b158fdf393";

	unsigned char seedKey[16];
	hex2ByteArray(seedKeyHex, seedKey, 16);

	char hardwareInfo[500];
	memset(hardwareInfo, 0, 500);
	int infoLen = getHardwareInfo(hardwareInfo);

	//printf("debug11111111111\n");

	//����
	char orginalData[600];
	memset(orginalData, 0, 600);

	strcat(orginalData, clientSN);
	strcat(orginalData, "_");
	strcat(orginalData, hardwareInfo);
	int info_len = strlen(orginalData);
	//printf("debug-client hd info:%s \n", orginalData);

	char md5Value[33];
	memset(md5Value, 0, 33);
	getMd5WithSeed(orginalData, info_len, (char*)seedKey, 16, md5Value);

	char outputData[600];
	memset(outputData, 0, 600);
	strcat(outputData, orginalData);
	strcat(outputData, "_");
	strcat(outputData, md5Value);
	printf("debug info:%s\n", outputData);

	int base64Len = 0;
	char* base64Content = encodeBase64(outputData, strlen(outputData), &base64Len);
	printf("you client certificate:%s \n", base64Content);
	free(base64Content);


	//base64Content ����������֮�󣬻᷵��һ���µ�base64�����ļ�����
	//���ܳ�pbkey,Ȼ�����pb��
}

void decodeServerPbkey(char *pbkeyBase64, int pbFileSize, unsigned char* pbkey) {

	char clientSn[] = "abc";
	char hardwareinfo[500];
	const char *seedKeyHash = "8874e9f4a5eec793873c56b158fdf393";
	unsigned char seedKey[16];

	getHardwareInfo(hardwareinfo);
	hex2ByteArray(seedKeyHash, seedKey, 16);

	int base64Len = 0;
	unsigned char* base64Content = decodeBase64(pbkeyBase64, strlen(pbkeyBase64), &base64Len);
	//unsigned char pbKey[50];
	decryptPbKey(base64Content, pbFileSize, clientSn, (char *)seedKey, pbkey);

}

int getPartData(char* srcdata, char token, int partNum, char* outData)
{
	int strLen = strlen(srcdata);
	int ind = 0;
	int partInd = 0;
	while (partInd < partNum && ind < strLen)
	{
		if (srcdata[ind] == token)
		{
			partInd++;
		}
		ind++;
	}

	if (partInd == partNum && ind < strLen)
	{
		int j = 0;
		while (srcdata[ind] != token && ind < strLen)
		{
			outData[j] = srcdata[ind];

			ind++;
			j++;
		}

	}

	return 1;

}


//=============
int main12() {

	/*char macAddress[38];
	getMacAddress(macAddress);
	printf("macAddress:%s\n ", macAddress);*/


	char hardwareInfo[500];
	memset(hardwareInfo, 0, 500);
	int infoLen = getHardwareInfo(hardwareInfo);

	printf("getHardwareInfo:%s\n ", hardwareInfo);


	int result = getHHHHHHH();
	printf("result = %d\n", result);

	/*
	//����pbKey
	char clientSN[] = "111111-55555555555";
	char seedKeyHex[] = "8874e9f4a5eec793873c56b158fdf393";


	char base64CipherPbKey[] ="BPe/zQomp/OOJjnovaw6TrjU/ee1CrAxwsCLkZBx+eGgWKH8v8Y446KfoL/976BY";

	int base64Len = 0;
	unsigned char* base64Content = decodeBase64(base64CipherPbKey, strlen(base64CipherPbKey), &base64Len);

	char seedKey[16];
	hex2ByteArray(seedKeyHex, (unsigned char* )seedKey, 16);

	unsigned char pbKey[16] ;
	decryptPbKey(base64Content,base64Len,clientSN,seedKey,pbKey);

	char out_str[33];
	for (int i = 0; i<16; i++)
	{
	sprintf(out_str + i * 2, "%02X", pbKey[i]);
	}
	printf("%s\n",out_str);


	char* pbkeyBase64 = "dkdl;d;d;d;;d;d;d;ldldldldldldldl";
	int pbfilesize = 12345;

	unsigned char pbkey[50];
	decodeServerPbkey(pbkeyBase64, pbfilesize, pbkey);


	int value = decryptPbKey(cipherData, MSG_LEN, clientSN, cipherPbKey, pbKey);
	if (value == 0) {
	return 0;
	}




	//�����ļ�
	char encodeFile[] = "test.dat.encode4";

	FILE* pfile = fopen(encodeFile, "rb");
	if (pfile == NULL)
	{
	printf("open pb file failed!! \n");
	return 0;
	}

	fseek(pfile, 0L, SEEK_END);
	int fileSize = ftell(pfile);
	fseek(pfile, 0L, SEEK_SET);

	printf("fileSize==>%d \n", fileSize);

	unsigned char *cipherContent = (unsigned char *)malloc(sizeof(char)*fileSize);
	int len = fread(cipherContent, 1, fileSize, pfile);
	fclose(pfile);

	unsigned char *pbContent = (unsigned char *)malloc(sizeof(char)*fileSize);
	memset(pbContent,0,fileSize);

	char pbkeyHex[]="88F26434D1B92EAE86AA6758BE4843BC";
	unsigned char pbkey[16];
	hex2ByteArray(pbkeyHex, (unsigned char* )pbkey, 16);

	decryptPbData(cipherContent, len, pbkey, pbContent);


	FILE *wfile = fopen("/home/chuanyhu/11111.dat", "wb");
	fwrite(pbContent, 33564727, 1, wfile);
	fclose(wfile);


	free(cipherContent);
	free(pbContent);
	*/
	return 1;
}
