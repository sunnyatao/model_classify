#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>


//#include <asm/types.h>

#include <openssl/md5.h>
#include <openssl/aes.h>


//#include <net/if.h>
//#include <arpa/inet.h>
//#include <sys/ioctl.h>
//#include <sys/socket.h>

#include "hard_info.h"
#include "base64.h"

#define AES_BITS 128
#define MSG_LEN 128

using namespace std;


/*
获取硬件信息
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

	//解密
	AES_KEY aes_key;
	if (AES_set_decrypt_key(pbKey, 128, &aes_key)<0)
	{
		printf("设置解密密钥失败!!\n");
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
	return 0;
}

/*
cipherData   服务器加密好的字符串
clientSN   用户输入的id
seedKey 用来加密  pbkey的 key
outPbKey  存储解密pb的key
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

	//处理
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

	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
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

	memset(bytes, 0,blen);
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

	//处理
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


	//base64Content 传到服务器之后，会返回一个新的base64，与文件长度
	//解密出pbkey,然后解密pb，
	return 0;
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


	/*
	//解密pbKey
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




	//解密文件
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
