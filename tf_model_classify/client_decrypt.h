

int inner_setupLicense();

int decryptPbKey(unsigned char *cipherData, int cipherDataLen, char *clientSN, char *seedKey, unsigned char *outPbKey);

int decryptPbData(unsigned char *cipherData, int cipherDataLen, unsigned char pbKey[], unsigned char *pbContent);

int getPartData(char* srcdata, char token, int partNum, char* outData);

int hex2ByteArray(const char * str, unsigned char * bytes, int blen);

unsigned char* decodeBase64(const char* ascii, int len, int *flen);