#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <sys/io.h>
#include <sys/stat.h> 

#include <sys/wait.h>  
#include <unistd.h>  

#include <fcntl.h>
#include <linux/hdreg.h>

#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <asm/types.h>
#include <errno.h>
#include <sys/socket.h>

#include <openssl/md5.h>
#include "base64.h"
#include <ctime>

//==============
#include <openssl/aes.h>

#include <dirent.h>
#include <unistd.h> 


#define AES_BITS 128
#define MSG_LEN 128

using namespace std;


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


int aesEncodeFile(char* srcFile, unsigned char pbKey[], char *outFile) {
	//读取文件内容
	FILE* sfile = fopen(srcFile, "rb");
	if (sfile == NULL) {
		printf("open srcFile failed!\n");
		return 0;
	}

	//生成密钥

	AES_KEY aes_key;
	int ret = AES_set_encrypt_key(pbKey, 128, &aes_key);
	if (ret<0) {
		printf("设置密钥失败!!\n");
		return 0;
	}

	printf("outFile = %s \n", outFile);
	//创建密文文件
	FILE* cfile = fopen(outFile, "wb");
	if (cfile == NULL) {
		printf("open cipher file failed!!\n");
		return 0;
	}

	//设置明文空间
	unsigned char plain[17] = { 0 };
	//生成密文空间
	unsigned char cipher[17] = { 0 };
	//加密
	int num = fread(plain, 1, 16, sfile);
	while (num != 0) {
		AES_ecb_encrypt(plain, cipher, &aes_key, AES_ENCRYPT);
		memset(plain, 0, 17);
		num = fread(plain, 1, 16, sfile);
		fwrite(cipher, 1, 16, cfile);
		// printf("cipher=%s\n",cipher);
	}
	fclose(cfile);
	fclose(sfile);

	return 1;
}

int aesEncodeKey(unsigned char* pbKey, int pbKeyLen, char* md5Value, unsigned char* outString)
{

	unsigned char iv[AES_BLOCK_SIZE];//加密的初始化向量
	for (int i = 0; i<AES_BLOCK_SIZE; ++i)//iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;
	AES_KEY aes;
	if (AES_set_encrypt_key((unsigned char*)md5Value, 128, &aes) < 0)
	{
		return 0;
	}

	AES_cbc_encrypt(pbKey, outString, pbKeyLen, &aes, iv, AES_ENCRYPT);
	return 1;

}

void encodeUserKey(unsigned char* pbKey, int pbKeyLen, char *clientSn, char *hardwareInfo, char *seedKey, unsigned char *safePbKey) {
	//md5
	char input[600];
	memset(input, 0, 600);

	strcpy(input, clientSn);
	strcat(input, "_");
	strcat(input, hardwareInfo);
	//strcat(input, "_");
	//strcat(input, seedKey);

	//printf("input==>%s \n", input);

	char md5Value[33];
	memset(md5Value, 0, 33);
	//printf("inputlen==>%d \n", strlen(input));
	getMd5WithSeed(input, strlen(input), seedKey, 16, md5Value);
	//getMd5(input,strlen(input), md5Value);
	//printf("pbkey sercet ==>%s \n", md5Value);

	int result = aesEncodeKey(pbKey, pbKeyLen, md5Value, safePbKey);

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

void checkUserInfo(char *inputBase64Data, char *pbKeyHex, char* outPbkeyBase64, char **clientSn) {

	int base64Len = 0;
	unsigned char* base64Content = decodeBase64(inputBase64Data, strlen(inputBase64Data), &base64Len);

	char seg[] = "_";
	char charlist[50][50] = { "" };
	int i = 0;
	char *substr = strtok((char *)base64Content, seg);

	while (substr != NULL) {
		strcpy(charlist[i], substr);
		i++;
		//printf("%s \n", substr);
		substr = strtok(NULL, seg);
	}

	*clientSn = charlist[0];
	char *cpuid = charlist[1];
	char *mac = charlist[2];

	char hardwareinfo[100];
	memset(hardwareinfo, 0, 100);
	strcat(hardwareinfo, cpuid);
	strcat(hardwareinfo, "_");
	strcat(hardwareinfo, mac);

	const char *seedKeyHex = "8874e9f4a5eec793873c56b158fdf393";

	unsigned char seedKey[16];
	hex2ByteArray(seedKeyHex, seedKey, 16);



	unsigned char pbKey[16];
	hex2ByteArray(pbKeyHex, pbKey, 16);
	unsigned char safePbKey[MSG_LEN];
	memset(safePbKey, 0, MSG_LEN);

	encodeUserKey(pbKey, 16, *clientSn, hardwareinfo, (char *)seedKey, safePbKey);
	//printf("outString:%s \n", outString);
	//printf("\n");
	char *pbKeyTemp = encodeBase64(safePbKey, 16, &base64Len);

	//printf("pbKeyTemp:%s \n", pbKeyTemp);

	strcpy(outPbkeyBase64, pbKeyTemp);

	free(pbKeyTemp);


}

//产生长度为length的随机字符串  
char* genRandomString(int length)
{
	int flag, i;
	char* string;

	if ((string = (char*)malloc(length)) == NULL)
	{
		return NULL;
	}

	for (i = 0; i < length; i++)
	{
		flag = rand() % 3;
		switch (flag)
		{
		case 0:
			string[i] = 'A' + rand() % 26;
			break;
		case 1:
			string[i] = 'a' + rand() % 26;
			break;
		case 2:
			string[i] = '0' + rand() % 10;
			break;
		default:
			string[i] = 'x';
			break;
		}
	}
	//string[length - 1] = '\0';

	return string;
}

void makePbKeyHex(char *pbKeyArray[5]) {

	char pbKeyFilePath[] = "/home/liutao/secpbs/pbKeyFile.dat";
	//读取文件内容
	FILE* rFile = fopen(pbKeyFilePath, "rb");
	if (rFile == NULL) {
		srand((unsigned)time(NULL));

		//创建pbkey
		FILE* wFile = fopen(pbKeyFilePath, "wb");
		for (int i = 0; i < 5; i++) {
			char* randomString = genRandomString(32);
			getMd5(randomString, 32, pbKeyArray[i]);

			printf("pbKeyArray[%d]==%s\n", i, pbKeyArray[i]);
			fwrite(pbKeyArray[i], 1, 32, wFile);

			if (i != 4)
				fwrite("_", 1, 1, wFile);
		}

		fclose(wFile);
	}
	else {
		//从文件中读取
		fseek(rFile, 0L, SEEK_END);
		int fileSize = ftell(rFile);
		fseek(rFile, 0L, SEEK_SET);

		char *content = (char *)malloc(sizeof(char)*fileSize);
		memset(content, 0, fileSize);

		int len = fread(content, 1, fileSize, rFile);
		printf("pbKeyArray size == %d\n", len);

		char seg[] = "_";
		int i = 0;
		char *subStr = strtok((char *)content, seg);

		while (subStr != NULL) {


			strcpy(pbKeyArray[i], subStr);

			//pbKeyArray[i] = subStr;

			i++;
			subStr = strtok(NULL, seg);
		}

		for (int j = 0;j<5;j++) {
			printf("pbKeyArray[%d]=%s\n", j, pbKeyArray[j]);
		}

		fclose(rFile);
		free(content);
	}
}

/*
type
1 加密pbkey
2 加密5个文件
*/
void makeContent(int type) {

	char *pbKeyHexArray[5];
	char a[200];
	pbKeyHexArray[0] = a;
	pbKeyHexArray[1] = a + 33;
	pbKeyHexArray[2] = a + 66;
	pbKeyHexArray[3] = a + 99;
	pbKeyHexArray[4] = a + 132;

	makePbKeyHex(pbKeyHexArray);

	char srcFileName[5][100] = { "/deeplearn_data/standard_test_models/pbs/frozen_model_noise_0511.pb",
		"/deeplearn_data/standard_test_models/pbs/threeclass_I_0516.pb",
		"/deeplearn_data/standard_test_models/pbs/threeclass_II_0516.pb",
		"/deeplearn_data/standard_test_models/pbs/threeclass_V1_0516.pb",
		"/deeplearn_data/standard_test_models/pbs/threeclass_V5_0516.pb" };




	//加密5个文件
	/*char srcFileName[5][100] = { "/home/liutao/secpbs/test.dat",
	"/home/liutao/secpbs/test.dat",
	"/home/liutao/secpbs/test.dat",
	"/home/liutao/secpbs/test.dat",
	"/home/liutao/secpbs/test.dat" };
	*/
	if (type == 1) {

		//加密pbkey
		char extraNameArray[5][6] = { "noise",
			"I",
			"II",
			"V1",
			"V5" };

		int pbSizeArray[5] = { 0 };

		for (int i = 0; i < 5; i++) {
			FILE* file = fopen(srcFileName[i], "rb");
			if (file != NULL) {
				fseek(file, 0L, SEEK_END);
				int fileSize = ftell(file);
				fseek(file, 0L, SEEK_SET);

				pbSizeArray[i] = fileSize;
				fclose(file);
			}
		}


		char base64[] = "MTExMTExMTExLTIyMjIyMi01NTU1NV9CRkVCRkJGRi0wMDA0MDZGMS0wMDAwMDAwMC0wMDAwMDAwMF8wQzpDNDo3QTo4Mzo3MTpFQV8xODkwNUY0MTNDNDQ3N0IxRjU2MkQ3NTMwQ0EzQ0U3MQ==";

		char pbKeyValue[5][1000];
		memset(pbKeyValue, 0, 5000);

		for (int i = 0; i < 5; i++)
		{
			char* pbKeyHex = pbKeyHexArray[i];
			char* extraName = extraNameArray[i];
			int pbSize = pbSizeArray[i];

			char outPbKeyBase64[100];
			memset(outPbKeyBase64, 0, 100);

			char *clientSn[33];
			memset(clientSn, 0, 33);
			checkUserInfo(base64, pbKeyHex, outPbKeyBase64, clientSn);
			printf("outPbKeyBase64 = %s \n", outPbKeyBase64);

			char pbKeyBase64[1000];
			memset(pbKeyBase64, 0, 1000);

			char string[25];
			sprintf(string, "%d", pbSize);

			strcat(pbKeyBase64, *clientSn);
			strcat(pbKeyBase64, ":");
			strcat(pbKeyBase64, extraName);
			strcat(pbKeyBase64, ":");
			strcat(pbKeyBase64, string);
			strcat(pbKeyBase64, ":");
			strcat(pbKeyBase64, outPbKeyBase64);

			strcpy(pbKeyValue[i], pbKeyBase64);

			printf("pbKeyBase64[%d]=%s\n", i, pbKeyBase64);
			printf("\n\n");
		}

		for (int i = 0; i < 5; i++) {
			printf("pbKeyValue[%d]=%s\n", i, pbKeyValue[i]);
		}

	}
	else if (type == 2) {

		//加密5个文件

		char outFileName[5][100] = { "/home/liutao/secpbs/safe_frozen_model_noise_0511.pb",
			"/home/liutao/secpbs/safe_threeclass_I_0516.pb",
			"/home/liutao/secpbs/safe_threeclass_II_0516.pb",
			"/home/liutao/secpbs/safe_threeclass_V1_0516.pb",
			"/home/liutao/secpbs/safe_threeclass_V5_0516.pb" };



		//加密5个文件
		/*
		char outFileName[5][100] = { "/home/liutao/secpbs/test.dat.encode0",
		"/home/liutao/secpbs/test.dat.encode1",
		"/home/liutao/secpbs/test.dat.encode2",
		"/home/liutao/secpbs/test.dat.encode3",
		"/home/liutao/secpbs/test.dat.encode4" };
		*/


		for (int i = 0; i < 5; i++) {

			unsigned char pbKey[16];
			hex2ByteArray(pbKeyHexArray[i], pbKey, 16);
			aesEncodeFile(srcFileName[i], pbKey, outFileName[i]);
		}

	}

}




/*
获取pbkeys里面的文件内容
*/

void get_pbkeys_file_content(char* file_path, char contains_pbkeys[5][256]) {


	//读取文件内容
	FILE* rFile = fopen(file_path, "rb");
	if (rFile == NULL) {
		return;
	}

	//从文件中读取
	fseek(rFile, 0L, SEEK_END);
	int fileSize = ftell(rFile);
	fseek(rFile, 0L, SEEK_SET);

	char *content = (char *)malloc(sizeof(char)*fileSize);
	memset(content, 0, fileSize);

	int len = fread(content, 1, fileSize, rFile);
	printf("pbKeyArray size == %d\n", len);

	char seg[] = "\n";
	int i = 0;
	char *subStr = strtok((char *)content, seg);

	while (subStr != NULL) {
		strcpy(contains_pbkeys[i], subStr);
		//pbKeyArray[i] = subStr;
		i++;
		subStr = strtok(NULL, seg);
	}
}



/*
获取pbkey的密钥  或者生成密钥
*/
void generatePbEncryptKey(char* file_path, char* pbKeyArray[5])
{

	char pbKeyFilePath[1000];
	memset(pbKeyFilePath, 0, 1000);

	strcat(pbKeyFilePath, file_path);
	strcat(pbKeyFilePath, "/");
	strcat(pbKeyFilePath, "pbkeys/");
	strcat(pbKeyFilePath, "pbkeys.dat");


	printf("pbKeyFilePath = %s \n", pbKeyFilePath);

	//读取文件内容
	FILE* rFile = fopen(pbKeyFilePath, "rb");
	if (rFile == NULL) {
		srand((unsigned)time(NULL));
		//创建pbkey
		for (int i = 0; i < 5; i++) {
			char* randomString = genRandomString(32);
			getMd5(randomString, 32, pbKeyArray[i]);
		}
	}
	else {

		char contains_pbkeys[5][256];
		get_pbkeys_file_content(pbKeyFilePath, contains_pbkeys);

		for (int m = 0; m < 5; m++)
		{
			char* subStr = contains_pbkeys[m];
			char seg_pbkey[] = "_";
			int j = 0;
			char *pbkey = strtok((char *)subStr, seg_pbkey);

			while (pbkey != NULL) {
				j++;
				if (j == 2)
				{
					strcpy(pbKeyArray[m], pbkey);
				}
				pbkey = strtok(NULL, seg_pbkey);
			}
		}

		for (int j = 0;j<5;j++) {
			printf("pbKeyArray[%d]=%s\n", j, pbKeyArray[j]);
		}
		fclose(rFile);
	}
}


/* 获取pb源文件的路径 与 加密文件的路径*/

void get_pb_file_path(char *input_path, char * safe_pb_dir, char srcFileName[5][256], char outFileName[5][256])
{
	char lead_names[5][8] = { "_noise_","_I_","_II_","_V1_","_V5_" };

	DIR *dirp;
	struct dirent *dp;
	dirp = opendir(input_path); //打开目录指针
								/*根据输入的文件路径  获取5个pb文件的绝对路径*/
	while ((dp = readdir(dirp)) != NULL) { //通过目录指针读目录
		char* file_name = dp->d_name;
		printf("file_name=========================    %s\n", file_name);
		for (int i = 0; i < 5;i++)
		{
			char* lead_name = lead_names[i];
			if (strstr(file_name, lead_name))
			{
				char sre_file_path[256];
				memset(sre_file_path, 0, 256);

				strcat(sre_file_path, input_path);
				strcat(sre_file_path, "/");
				strcat(sre_file_path, file_name);

				//srcFileName[i] = sre_file_path;
				strcpy(srcFileName[i], sre_file_path);
				printf("srcFileName[%d] = %s \n", i, sre_file_path);


				char out_file_path[256];
				memset(out_file_path, 0, 256);
				strcat(out_file_path, safe_pb_dir);
				strcat(out_file_path, "/safe_");
				strcat(out_file_path, file_name);
				//outFileName[i] = out_file_path;
				strcpy(outFileName[i], out_file_path);
				printf("outFileName[%d] = %s \n", i, out_file_path);

				break;
			}
		}
	}

	(void)closedir(dirp); //关闭目录
}

/*
将pb的密钥 与 文件的路径与大小 存到dat里面
*/

void save_pbkeys_content(char* input_path, int pbSizeArray[5], char* pbKeyHexArray[5], char outFileName[5][256])
{
	/*创建一个pbkeys文件夹*/
	char pbkeys_path[256];
	memset(pbkeys_path, 0, 256);
	strcat(pbkeys_path, input_path);
	strcat(pbkeys_path, "/pbkeys");
	int access2 = access(pbkeys_path, 0);
	if (access2)
	{
		int success = mkdir(pbkeys_path, 0777);
	}
	strcat(pbkeys_path, "/pbkeys.dat");
	FILE* pbkeyfile = fopen(pbkeys_path, "wb");
	if (pbkeyfile == NULL) {
		printf("open pbkeys_path failed!\n");
		return;
	}

	char w_text[5000];
	memset(w_text, 0, 5000);

	for (int i = 0; i < 5; i++) {
		int size = pbSizeArray[i];
		char pb_size[20];
		sprintf(pb_size, "%d", size);
		strcat(w_text, pb_size);
		strcat(w_text, "_");
		strcat(w_text, pbKeyHexArray[i]);
		strcat(w_text, "_");
		strcat(w_text, outFileName[i]);
		if (i != 4)
		{
			strcat(w_text, "\n");
		}
	}

	fprintf(pbkeyfile, w_text);
	fclose(pbkeyfile);
}




/*
根据配置的源文件路径，输入文件路径， 加密pb
*/

int encrypt_pb_file(char * pb_dir, char * safe_pb_dir) {

	char srcFileName[5][256];
	char outFileName[5][256];

	get_pb_file_path(pb_dir, safe_pb_dir, srcFileName, outFileName);

	/*读取文件大小*/
	int pbSizeArray[5] = { 0 };

	for (int i = 0; i < 5; i++) {
		FILE* file = fopen(srcFileName[i], "rb");
		if (file != NULL) {
			fseek(file, 0L, SEEK_END);
			int fileSize = ftell(file);
			fseek(file, 0L, SEEK_SET);
			pbSizeArray[i] = fileSize;
			fclose(file);
		}
	}

	char *pbKeyHexArray[5];
	char a[200];
	pbKeyHexArray[0] = a;
	pbKeyHexArray[1] = a + 33;
	pbKeyHexArray[2] = a + 66;
	pbKeyHexArray[3] = a + 99;
	pbKeyHexArray[4] = a + 132;

	generatePbEncryptKey(pb_dir, pbKeyHexArray);

	/*加密pb文件*/
	for (int i = 0; i < 5; i++) {
		unsigned char pbKey[16];
		hex2ByteArray(pbKeyHexArray[i], pbKey, 16);
		aesEncodeFile(srcFileName[i], pbKey, outFileName[i]);
	}

	/*保存信息*/
	save_pbkeys_content(pb_dir, pbSizeArray, pbKeyHexArray, outFileName);

	return 1;

}



/*加密pbkeys */
int createUserLicence(char * safe_pb_dir, char * user_certificate) {


	char lead_names[5][6] = { "noise","I","II","V1","V5" };
	char out_path[256];
	memset(out_path, 0, 256);
	strcat(out_path, safe_pb_dir);
	strcat(out_path, "/pbkeys.dat");


	int pbSizeArray[5];
	memset(pbSizeArray, 0, 5);

	char *pbKeyHexArray[5];
	char a[200];
	pbKeyHexArray[0] = a;
	pbKeyHexArray[1] = a + 33;
	pbKeyHexArray[2] = a + 66;
	pbKeyHexArray[3] = a + 99;
	pbKeyHexArray[4] = a + 132;

	char contains_pbkeys[5][256];

	get_pbkeys_file_content(out_path, contains_pbkeys);

	for (int m = 0; m < 5; m++)
	{
		char* subStr = contains_pbkeys[m];
		printf("contains_pbkeys[%d] = %s \n ", m, subStr);
		char seg_pbkey[] = "_";
		int j = 0;
		char *pbkey = strtok((char *)subStr, seg_pbkey);

		while (pbkey != NULL) {
			j++;
			if (j == 1)
			{
				pbSizeArray[m] = atoi(pbkey);
			}

			if (j == 2)
			{
				strcpy(pbKeyHexArray[m], pbkey);
			}
			pbkey = strtok(NULL, seg_pbkey);
		}
	}




	char licence_path[256];
	memset(licence_path, 0, 256);
	strcat(licence_path, safe_pb_dir);
	strcat(licence_path, "/licence.dat");
	FILE* licenec_file = fopen(licence_path, "wb");
	if (licenec_file == NULL) {
		printf("open pbkeys_path failed!\n");
	}


	char pbKeyValue[5][1000];

	memset(pbKeyValue, 0, 5000);

	

	for (int i = 0; i < 5; i++)
	{
		char* pbKeyHex = pbKeyHexArray[i];
		char* extraName = lead_names[i];
		int pbSize = pbSizeArray[i];



		char outPbKeyBase64[100];
		memset(outPbKeyBase64, 0, 100);

		char *clientSn[33];
		memset(clientSn, 0, 33);
		checkUserInfo(user_certificate, pbKeyHex, outPbKeyBase64, clientSn);

		char pbKeyBase64[1000];
		memset(pbKeyBase64, 0, 1000);

		char string[25];
		sprintf(string, "%d", pbSize);
		strcat(pbKeyBase64, *clientSn);
		strcat(pbKeyBase64, ":");
		strcat(pbKeyBase64, extraName);
		strcat(pbKeyBase64, ":");
		strcat(pbKeyBase64, string);
		strcat(pbKeyBase64, ":");
		strcat(pbKeyBase64, outPbKeyBase64);
		strcpy(pbKeyValue[i], pbKeyBase64);

		fprintf(licenec_file, pbKeyValue[i]);
		if (i != 4)
		{
			fprintf(licenec_file, "\n");
		}
	}

	printf("pbKeyHexArray\n");
	for (int i = 0; i < 5; i++) {
		printf("%s\n",pbKeyValue[i]);
	}

	
	fclose(licenec_file);


}



int main(int argc, char *argv[]) {


	printf("0 =%s ,  1=%s   2=%s   3=%s \n", argv[0], argv[1], argv[2], argv[3]);

	if (argc < 4)
	{
		printf("please input parameter:  \nencryptPb  pbdir safe_pb_dir\ncreateUserLicence  safe_pb_dir  user_certificate\n");
		return -1;
	}

	if (strcmp(argv[1], "encryptPb") == 0)
	{
		printf("use pb_dir %s , safe_pd_dir %s.", argv[2], argv[3]);
		encrypt_pb_file(argv[2], argv[3]);
	}

	if (strcmp(argv[1], "createUserLicence") == 0)
	{
		printf("use safe_pb_dir: %s , user_certificate:%s.", argv[2], argv[3]);
		createUserLicence(argv[2], argv[3]);
	}



	//printf("encrypt new pb input 1  encrypt pbkey input 2 \n");

	//int type;
	//scanf("%d", &type);
	//if (type == 1)
	//{
	//	// 加密新的pb文件，  输入pb文件所在的文件夹，读取该文件夹下的license文件夹下是否有秘钥，
	//	//如果没有就生成秘钥，有就读取出来，还要生成一个safa_pb文件夹 
	//	//然后对文件加密，将pb文件大小，密钥，safe_pb的路径存到license文件夹下的pbKeyFile.dat中
	//	encrypt_pb_file();
	//}
	//else if (type == 2)
	//{
	//}
	//else
	//{
	//	printf("input error,again");
	//}


	//makeContent(2);

	//printf("\n");
	return 1;
}
