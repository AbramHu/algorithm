

#ifndef _Included_jni_security_DES
#define _Included_jni_security_DES


#define KEY							"$k6d)*@8"   //��Կ

class CDesCode
{
public:
	// �ļ�����
	static int EncryptForFile(char *plainFile, char *keyStr,char *cipherFile);
	// �ļ�����
	static int DecryptForFile(char *cipherFile, char *keyStr,char *plainFile);
	// ���ݼ���
	static int EncryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *encodeStr);
	// ���ݽ���
	static int DecryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *decodeStr);

};
#endif
