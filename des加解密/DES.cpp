#include "stdafx.h"

#include "DES.h"

#include <stdio.h>
#include <memory.h>


#define PLAIN_FILE_OPEN_ERROR -1
#define KEY_FILE_OPEN_ERROR -2
#define CIPHER_FILE_OPEN_ERROR -3
#define OK 1 

//////////////////////////////////////////////////////////////////////////////////
//发送映射
const unsigned char g_SendByteMap[256]=
{
	0x70,0x2F,0x40,0x5F,0x44,0x8E,0x6E,0x45,0x7E,0xAB,0x2C,0x1F,0xB4,0xAC,0x9D,0x91,
	0x0D,0x36,0x9B,0x0B,0xD4,0xC4,0x39,0x74,0xBF,0x23,0x16,0x14,0x06,0xEB,0x04,0x3E,
	0x12,0x5C,0x8B,0xBC,0x61,0x63,0xF6,0xA5,0xE1,0x65,0xD8,0xF5,0x5A,0x07,0xF0,0x13,
	0xF2,0x20,0x6B,0x4A,0x24,0x59,0x89,0x64,0xD7,0x42,0x6A,0x5E,0x3D,0x0A,0x77,0xE0,
	0x80,0x27,0xB8,0xC5,0x8C,0x0E,0xFA,0x8A,0xD5,0x29,0x56,0x57,0x6C,0x53,0x67,0x41,
	0xE8,0x00,0x1A,0xCE,0x86,0x83,0xB0,0x22,0x28,0x4D,0x3F,0x26,0x46,0x4F,0x6F,0x2B,
	0x72,0x3A,0xF1,0x8D,0x97,0x95,0x49,0x84,0xE5,0xE3,0x79,0x8F,0x51,0x10,0xA8,0x82,
	0xC6,0xDD,0xFF,0xFC,0xE4,0xCF,0xB3,0x09,0x5D,0xEA,0x9C,0x34,0xF9,0x17,0x9F,0xDA,
	0x87,0xF8,0x15,0x05,0x3C,0xD3,0xA4,0x85,0x2E,0xFB,0xEE,0x47,0x3B,0xEF,0x37,0x7F,
	0x93,0xAF,0x69,0x0C,0x71,0x31,0xDE,0x21,0x75,0xA0,0xAA,0xBA,0x7C,0x38,0x02,0xB7,
	0x81,0x01,0xFD,0xE7,0x1D,0xCC,0xCD,0xBD,0x1B,0x7A,0x2A,0xAD,0x66,0xBE,0x55,0x33,
	0x03,0xDB,0x88,0xB2,0x1E,0x4E,0xB9,0xE6,0xC2,0xF7,0xCB,0x7D,0xC9,0x62,0xC3,0xA6,
	0xDC,0xA7,0x50,0xB5,0x4B,0x94,0xC0,0x92,0x4C,0x11,0x5B,0x78,0xD9,0xB1,0xED,0x19,
	0xE9,0xA1,0x1C,0xB6,0x32,0x99,0xA3,0x76,0x9E,0x7B,0x6D,0x9A,0x30,0xD6,0xA9,0x25,
	0xC7,0xAE,0x96,0x35,0xD0,0xBB,0xD2,0xC8,0xA2,0x08,0xF3,0xD1,0x73,0xF4,0x48,0x2D,
	0x90,0xCA,0xE2,0x58,0xC1,0x18,0x52,0xFE,0xDF,0x68,0x98,0x54,0xEC,0x60,0x43,0x0F
};

//接收映射
const unsigned char g_RecvByteMap[256]=
{
	0x51,0xA1,0x9E,0xB0,0x1E,0x83,0x1C,0x2D,0xE9,0x77,0x3D,0x13,0x93,0x10,0x45,0xFF,
	0x6D,0xC9,0x20,0x2F,0x1B,0x82,0x1A,0x7D,0xF5,0xCF,0x52,0xA8,0xD2,0xA4,0xB4,0x0B,
	0x31,0x97,0x57,0x19,0x34,0xDF,0x5B,0x41,0x58,0x49,0xAA,0x5F,0x0A,0xEF,0x88,0x01,
	0xDC,0x95,0xD4,0xAF,0x7B,0xE3,0x11,0x8E,0x9D,0x16,0x61,0x8C,0x84,0x3C,0x1F,0x5A,
	0x02,0x4F,0x39,0xFE,0x04,0x07,0x5C,0x8B,0xEE,0x66,0x33,0xC4,0xC8,0x59,0xB5,0x5D,
	0xC2,0x6C,0xF6,0x4D,0xFB,0xAE,0x4A,0x4B,0xF3,0x35,0x2C,0xCA,0x21,0x78,0x3B,0x03,
	0xFD,0x24,0xBD,0x25,0x37,0x29,0xAC,0x4E,0xF9,0x92,0x3A,0x32,0x4C,0xDA,0x06,0x5E,
	0x00,0x94,0x60,0xEC,0x17,0x98,0xD7,0x3E,0xCB,0x6A,0xA9,0xD9,0x9C,0xBB,0x08,0x8F,
	0x40,0xA0,0x6F,0x55,0x67,0x87,0x54,0x80,0xB2,0x36,0x47,0x22,0x44,0x63,0x05,0x6B,
	0xF0,0x0F,0xC7,0x90,0xC5,0x65,0xE2,0x64,0xFA,0xD5,0xDB,0x12,0x7A,0x0E,0xD8,0x7E,
	0x99,0xD1,0xE8,0xD6,0x86,0x27,0xBF,0xC1,0x6E,0xDE,0x9A,0x09,0x0D,0xAB,0xE1,0x91,
	0x56,0xCD,0xB3,0x76,0x0C,0xC3,0xD3,0x9F,0x42,0xB6,0x9B,0xE5,0x23,0xA7,0xAD,0x18,
	0xC6,0xF4,0xB8,0xBE,0x15,0x43,0x70,0xE0,0xE7,0xBC,0xF1,0xBA,0xA5,0xA6,0x53,0x75,
	0xE4,0xEB,0xE6,0x85,0x14,0x48,0xDD,0x38,0x2A,0xCC,0x7F,0xB1,0xC0,0x71,0x96,0xF8,
	0x3F,0x28,0xF2,0x69,0x74,0x68,0xB7,0xA3,0x50,0xD0,0x79,0x1D,0xFC,0xCE,0x8A,0x8D,
	0x2E,0x62,0x30,0xEA,0xED,0x2B,0x26,0xB9,0x81,0x7C,0x46,0x89,0x73,0xA2,0xF7,0x72
};
//////////////////////////////////////////////////////////////////////////////////


/*初始置换表IP*/
int IP_Table[64] = { 57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7,
	56,48,40,32,24,16,8,0,
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6}; 
/*逆初始置换表IP^-1*/
int IP_1_Table[64] = {39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9,49,17,57,25,
	32,0,40,8,48,16,56,24};

/*扩充置换表E*/
int E_Table[48] = {31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8,9,10,11,12,
	11,12,13,14,15,16,
	15,16,17,18,19,20,
	19,20,21,22,23,24,
	23,24,25,26,27,28,
	27,28,29,30,31, 0};

/*置换函数P*/
int P_Table[32] = {45,6,19,24,28,11,27,16,
	0,14,22,45,4,17,32,1,
	1,7,23,13,31,26,2,8,
	18,12,29,5,21,10,3,24};

/*S盒*/
int S[8][4][16] =
	/*S1*/
{{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
/*S2*/
{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
/*S3*/
{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
/*S4*/
{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
/*S5*/
{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
/*S6*/
{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
/*S7*/
{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
/*S8*/
{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
/*置换选择1*/
int PC_1[56] = {56,48,40,32,24,16,8,
	0,57,49,41,33,25,17,
	9,1,58,50,42,34,26,
	18,10,2,59,51,43,35,
	62,54,46,38,30,22,14,
	6,61,53,45,37,29,21,
	13,5,60,52,44,36,28,
	20,12,4,27,19,11,3};

/*置换选择2*/
int PC_2[48] = {13,16,10,23,0,4,2,27,
	14,5,20,9,22,18,11,3,
	25,7,15,6,26,19,12,1,
	40,51,30,36,46,54,29,39,
	50,44,32,46,43,48,38,55,
	33,52,45,41,49,35,28,31};

/*对左移次数的规定*/
int MOVE_TIMES[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; 

int ByteToBit(char ch,char bit[8]);
int BitToByte(char bit[8],char *ch);
int Char8ToBit64(char ch[8],char bit[64]);
int Bit64ToChar8(char bit[64],char ch[8]);
int DES_MakeSubKeys(char key[64],char subKeys[16][48]);
int DES_PC1_Transform(char key[64], char tempbts[56]);
int DES_PC2_Transform(char key[56], char tempbts[48]);
int DES_ROL(char data[56], int time);
int DES_IP_Transform(char data[64]);
int DES_IP_1_Transform(char data[64]);
int DES_E_Transform(char data[48]);
int DES_P_Transform(char data[32]);
int DES_SBOX(char data[48]);
int DES_XOR(char R[48], char L[48],int count);
int DES_Swap(char left[32],char right[32]);
int DES_EncryptBlock(char plainBlock[8], char subKeys[16][48], char cipherBlock[8]);
int DES_DecryptBlock(char cipherBlock[8], char subKeys[16][48], char plainBlock[8]);
int DES_Encrypt(char *plainFile, char *keyStr,char *cipherFile);
int DES_Decrypt(char *cipherFile, char *keyStr,char *plainFile); 

/*字节转换成二进制*/
int ByteToBit(char ch, char bit[8]){
	int cnt;
	for(cnt = 0;cnt < 8; cnt++){
		*(bit+cnt) = (ch>>cnt)&1;
	}
	return 0;
}

/*二进制转换成字节*/
int BitToByte(char bit[8],char *ch){
	int cnt;
	for(cnt = 0;cnt < 8; cnt++){
		*ch |= *(bit + cnt)<<cnt;
	}
	return 0;
}

/*将长度为8的字符串转为二进制位串*/
int Char8ToBit64(char ch[8],char bit[64]){
	int cnt;
	for(cnt = 0; cnt < 8; cnt++){ 
		ByteToBit(*(ch+cnt),bit+(cnt<<3));
	}
	return 0;
}

/*将二进制位串转为长度为8的字符串*/
int Bit64ToChar8(char bit[64],char ch[8]){
	int cnt;
	memset(ch,0,8);
	for(cnt = 0; cnt < 8; cnt++){
		BitToByte(bit+(cnt<<3),ch+cnt);
	}
	return 0;
}

/*生成子密钥*/
int DES_MakeSubKeys(char key[64],char subKeys[16][48]){
	char temp[56];
	int cnt;
	DES_PC1_Transform(key,temp);/*PC1置换*/
	for(cnt = 0; cnt < 16; cnt++){/*16轮跌代，产生16个子密钥*/
		DES_ROL(temp,MOVE_TIMES[cnt]);/*循环左移*/
		DES_PC2_Transform(temp,subKeys[cnt]);/*PC2置换，产生子密钥*/
	}
	return 0;
}

/*密钥置换1*/
int DES_PC1_Transform(char key[64], char tempbts[56]){
	int cnt; 
	for(cnt = 0; cnt < 56; cnt++){
		tempbts[cnt] = key[PC_1[cnt]];
	}
	return 0;
}

/*密钥置换2*/
int DES_PC2_Transform(char key[56], char tempbts[48]){
	int cnt;
	for(cnt = 0; cnt < 48; cnt++){
		tempbts[cnt] = key[PC_2[cnt]];
	}
	return 0;
}

/*循环左移*/
int DES_ROL(char data[56], int time){
	char temp[56];

	/*保存将要循环移动到右边的位*/
	memcpy(temp,data,time);
	memcpy(temp+time,data+28,time);

	/*前28位移动*/
	memcpy(data,data+time,28-time);
	memcpy(data+28-time,temp,time);

	/*后28位移动*/
	memcpy(data+28,data+28+time,28-time);
	memcpy(data+56-time,temp+time,time); 

	return 0;
}

/*IP置换*/
int DES_IP_Transform(char data[64]){
	int cnt;
	char temp[64];
	for(cnt = 0; cnt < 64; cnt++){
		temp[cnt] = data[IP_Table[cnt]];
	}
	memcpy(data,temp,64);
	return 0;
}

/*IP逆置换*/
int DES_IP_1_Transform(char data[64]){
	int cnt;
	char temp[64];
	for(cnt = 0; cnt < 64; cnt++){
		temp[cnt] = data[IP_1_Table[cnt]];
	}
	memcpy(data,temp,64);
	return 0;
}

/*扩展置换*/
int DES_E_Transform(char data[48]){
	int cnt;
	char temp[48];
	for(cnt = 0; cnt < 48; cnt++){
		temp[cnt] = data[E_Table[cnt]];
	}
	memcpy(data,temp,48);
	return 0;
}

/*P置换*/
int DES_P_Transform(char data[32]){
	int cnt;
	char temp[32];
	for(cnt = 0; cnt < 32; cnt++){
		temp[cnt] = data[P_Table[cnt]];
	}
	memcpy(data,temp,32);
	return 0;
}

/*异或*/
int DES_XOR(char R[48], char L[48] ,int count){
	int cnt;
	for(cnt = 0; cnt < count; cnt++){
		R[cnt] ^= L[cnt];
	}
	return 0;
}

/*S盒置换*/
int DES_SBOX(char data[48]){
	int cnt;
	int line,row,output;
	int cur1,cur2;
	for(cnt = 0; cnt < 8; cnt++){
		cur1 = cnt*6;
		cur2 = cnt<<2;

		/*计算在S盒中的行与列*/
		line = (data[cur1]<<1) + data[cur1+5];
		row = (data[cur1+1]<<3) + (data[cur1+2]<<2)
			+ (data[cur1+3]<<1) + data[cur1+4];
		output = S[cnt][line][row];

		/*化为2进制*/
		data[cur2] = (output&0X08)>>3;
		data[cur2+1] = (output&0X04)>>2;
		data[cur2+2] = (output&0X02)>>1;
		data[cur2+3] = output&0x01;
	}
	return 0;
}

/*交换*/
int DES_Swap(char left[32], char right[32]){
	char temp[32];
	memcpy(temp,left,32);
	memcpy(left,right,32); 
	memcpy(right,temp,32);
	return 0;
}

/*加密单个分组*/
int DES_EncryptBlock(char plainBlock[8], char subKeys[16][48], char cipherBlock[8]){
	char plainBits[64];
	char copyRight[48];
	int cnt;

	Char8ToBit64(plainBlock,plainBits); 
	/*初始置换（IP置换）*/
	DES_IP_Transform(plainBits);

	/*16轮迭代*/
	for(cnt = 0; cnt < 16; cnt++){ 
		memcpy(copyRight,plainBits+32,32);
		/*将右半部分进行扩展置换，从32位扩展到48位*/
		DES_E_Transform(copyRight);
		/*将右半部分与子密钥进行异或操作*/
		DES_XOR(copyRight,subKeys[cnt],48); 
		/*异或结果进入S盒，输出32位结果*/
		DES_SBOX(copyRight);
		/*P置换*/
		DES_P_Transform(copyRight);
		/*将明文左半部分与右半部分进行异或*/
		DES_XOR(plainBits,copyRight,32);
		if(cnt != 15){
			/*最终完成左右部的交换*/
			DES_Swap(plainBits,plainBits+32);
		}
	}
	/*逆初始置换（IP^1置换）*/
	DES_IP_1_Transform(plainBits);
	Bit64ToChar8(plainBits,cipherBlock);
	return 0;
}

/*解密单个分组*/
int DES_DecryptBlock(char cipherBlock[8], char subKeys[16][48],char plainBlock[8]){
	char cipherBits[64];
	char copyRight[48];
	int cnt;

	Char8ToBit64(cipherBlock,cipherBits); 
	/*初始置换（IP置换）*/
	DES_IP_Transform(cipherBits);

	/*16轮迭代*/
	for(cnt = 15; cnt >= 0; cnt--){
		memcpy(copyRight,cipherBits+32,32);
		/*将右半部分进行扩展置换，从32位扩展到48位*/
		DES_E_Transform(copyRight);
		/*将右半部分与子密钥进行异或操作*/
		DES_XOR(copyRight,subKeys[cnt],48); 
		/*异或结果进入S盒，输出32位结果*/
		DES_SBOX(copyRight);
		/*P置换*/
		DES_P_Transform(copyRight); 
		/*将明文左半部分与右半部分进行异或*/
		DES_XOR(cipherBits,copyRight,32);
		if(cnt != 0){
			/*最终完成左右部的交换*/
			DES_Swap(cipherBits,cipherBits+32);
		}
	}
	/*逆初始置换（IP^1置换）*/
	DES_IP_1_Transform(cipherBits);
	Bit64ToChar8(cipherBits,plainBlock);
	return 0;
}

/*加密文件*/
int CDesCode::EncryptForFile(char *plainFile, char *keyStr,char *cipherFile){
	FILE *plain,*cipher;
	size_t count;
	char plainBlock[8],cipherBlock[8],keyBlock[8];
	char bKey[64];
	char subKeys[16][48];
	if((plain = fopen(plainFile,"rb")) == NULL){
		return PLAIN_FILE_OPEN_ERROR;
	}
	if((cipher = fopen(cipherFile,"wb")) == NULL){
		return CIPHER_FILE_OPEN_ERROR;
	}
	/*设置密钥*/
	memcpy(keyBlock,keyStr,8);
	/*将密钥转换为二进制流*/
	Char8ToBit64(keyBlock,bKey);
	/*生成子密钥*/
	DES_MakeSubKeys(bKey,subKeys);

	while(!feof(plain)){
		/*每次读8个字节，并返回成功读取的字节数*/
		if((count = fread(plainBlock,sizeof(char),8,plain)) == 8){
			DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
			fwrite(cipherBlock,sizeof(char),8,cipher); 
		}
	}
	if(count){
		/*填充*/
		memset(plainBlock + count,'\0',7 - count);
		/*最后一个字符保存包括最后一个字符在内的所填充的字符数量*/
		plainBlock[7] = 8 - count;
		DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
		fwrite(cipherBlock,sizeof(char),8,cipher);
	}
	fclose(plain);
	fclose(cipher);
	return OK;
}

/*解密文件*/
int CDesCode::DecryptForFile(char *cipherFile, char *keyStr,char *plainFile){
	FILE *plain, *cipher;
	int count,times = 0;
	long fileLen;
	char plainBlock[8],cipherBlock[8],keyBlock[8];
	char bKey[64];
	char subKeys[16][48];
	if((cipher = fopen(cipherFile,"rb")) == NULL){
		return CIPHER_FILE_OPEN_ERROR;
	}
	if((plain = fopen(plainFile,"wb")) == NULL){
		return PLAIN_FILE_OPEN_ERROR;
	}

	/*设置密钥*/
	memcpy(keyBlock,keyStr,8);
	/*将密钥转换为二进制流*/
	Char8ToBit64(keyBlock,bKey);
	/*生成子密钥*/
	DES_MakeSubKeys(bKey,subKeys);

	/*取文件长度 */
	fseek(cipher,0,SEEK_END);/*将文件指针置尾*/
	fileLen = ftell(cipher); /*取文件指针当前位置*/
	rewind(cipher); /*将文件指针重指向文件头*/
	while(1){
		/*密文的字节数一定是8的整数倍*/
		fread(cipherBlock,sizeof(char),8,cipher);
		DES_DecryptBlock(cipherBlock,subKeys,plainBlock); 
		times += 8;
		if(times < fileLen){
			fwrite(plainBlock,sizeof(char),8,plain);
		}
		else{
			break;
		}
	}
	/*判断末尾是否被填充*/
	if(plainBlock[7] < 8){
		for(count = 8 - plainBlock[7]; count < 7; count++){
			if(plainBlock[count] != '\0'){
				break;
			}
		}
	}
	if(count == 7){/*有填充*/
		fwrite(plainBlock,sizeof(char),8 - plainBlock[7],plain);
	}
	else{/*无填充*/
		fwrite(plainBlock,sizeof(char),8,plain);
	}

	fclose(plain);
	fclose(cipher);
	return OK;
}

/*加密字符串*/
int CDesCode::EncryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *encodeStr){
	unsigned int count = size / 8;
	int tail = size % 8;
	unsigned int i = 0;
	char plainBlock[8],cipherBlock[8],keyBlock[8];
	char bKey[64];
	char subKeys[16][48];
	int retCount = 0;

	//映射
	for (i = 0; i < size; i++)
	{
		srcStr[i] = (char)g_SendByteMap[(unsigned char)srcStr[i]];
	}
	i = 0;

	/*设置密钥*/
	memcpy(keyBlock,keyStr,8);
	/*将密钥转换为二进制流*/
	Char8ToBit64(keyBlock,bKey);
	/*生成子密钥*/
	DES_MakeSubKeys(bKey,subKeys);

	while(i < count){
		/*每次读8个字节，并返回成功读取的字节数*/
		memcpy(plainBlock, srcStr+i*8, 8);
		DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
		memcpy(encodeStr+i*8, cipherBlock, 8);
		retCount += 8;
		++i;
	}
	if(tail){
		/*填充*/
		memcpy(plainBlock, srcStr+count*8, tail);
		memset(plainBlock+tail, '\0', 7 - tail);
		/*最后一个字符保存包括最后一个字符在内的所填充的字符数量*/
		plainBlock[7] = 8 - tail;

		DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
		memcpy(encodeStr+count*8, cipherBlock, 8);
		retCount += 8;
	}
	return retCount;
}

/*解密字符串*/
int CDesCode::DecryptForByte(char *srcStr,  unsigned int size, char *keyStr, char *decodeStr){
	int count = size / 8;
	int i = 0;
	int times = 0;
	char plainBlock[8],cipherBlock[8],keyBlock[8];
	char bKey[64];
	char subKeys[16][48];
	int retCount = 0;

	if (count == 0)
	{
		return retCount;
	}

	/*设置密钥*/
	memcpy(keyBlock,keyStr,8);
	/*将密钥转换为二进制流*/
	Char8ToBit64(keyBlock,bKey);
	/*生成子密钥*/
	DES_MakeSubKeys(bKey,subKeys);


	while(1){
		/*每次读8个字节，并返回成功读取的字节数*/
		memcpy(cipherBlock, srcStr+i*8, 8);
		DES_DecryptBlock(cipherBlock,subKeys,plainBlock);
		if (i < count-1){
			memcpy(decodeStr+i*8, plainBlock, 8);
			retCount += 8;
		}
		else{
			break;
		}
		++i;
	}
	/*判断末尾是否被填充*/
	while (1)
	{
		if(1 < plainBlock[7] && plainBlock[7] < 8)
		{
			for(i = 8 - plainBlock[7]; i < 7; i++){
				if(plainBlock[i] != '\0'){
					break;
				}
			}

			if(i == 7){/*有填充*/
				memcpy(decodeStr+count*8-8, plainBlock, 8 - plainBlock[7]);
				retCount += (8 - plainBlock[7]);
				break;
			}
		}
		/*无填充*/
		memcpy(decodeStr+count*8-8, plainBlock, 8);
		retCount += 8;
		break;
	}

	//映射
	for (i = 0; i < retCount; i++)
	{
		decodeStr[i] = (char)g_RecvByteMap[(unsigned char)decodeStr[i]];
	}

	return retCount;
}