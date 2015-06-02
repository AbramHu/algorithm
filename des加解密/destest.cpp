// destest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "DES.h"

int _tmain(int argc, _TCHAR* argv[])
{
	char srcStr[1024] = {0};

	while(1)
	{

		memset(srcStr ,0, sizeof(srcStr));
	printf("加密串：");
	scanf("%s", srcStr);

	printf("\n加密前(%d)", strlen(srcStr));

	int count = CDesCode::EncryptForByte(srcStr, strlen(srcStr), KEY, srcStr);

	printf("\n加密后(%d)：%s\n", count, srcStr);
	printf("执行解密....\n");
	
	count = CDesCode::DecryptForByte(srcStr, strlen(srcStr), KEY, srcStr);

	srcStr[count] = 0;

	printf("解密后(%d)：%s\n", count, srcStr);

		}
	getchar();
	getchar();

	return 0;
}

