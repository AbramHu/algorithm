// destest.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "DES.h"

int _tmain(int argc, _TCHAR* argv[])
{
	char srcStr[1024] = {0};

	while(1)
	{

		memset(srcStr ,0, sizeof(srcStr));
	printf("���ܴ���");
	scanf("%s", srcStr);

	printf("\n����ǰ(%d)", strlen(srcStr));

	int count = CDesCode::EncryptForByte(srcStr, strlen(srcStr), KEY, srcStr);

	printf("\n���ܺ�(%d)��%s\n", count, srcStr);
	printf("ִ�н���....\n");
	
	count = CDesCode::DecryptForByte(srcStr, strlen(srcStr), KEY, srcStr);

	srcStr[count] = 0;

	printf("���ܺ�(%d)��%s\n", count, srcStr);

		}
	getchar();
	getchar();

	return 0;
}

