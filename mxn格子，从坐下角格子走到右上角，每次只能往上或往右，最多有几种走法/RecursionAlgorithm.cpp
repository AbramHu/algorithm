// RecursionAlgorithm.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

int CountPath(int m, int n)
{
	if (m==1 || n == 1) 
		return 1;
	else
		return CountPath(m-1, n) + CountPath(m, n-1);
}

int _tmain(int argc, _TCHAR* argv[])
{
	int m = 0;
	int n = 0;

	while(1)
	{

	printf("========================\n输入行数m:");
	scanf("%d", &m);
	printf("\n输入列数n:");
	scanf("%d",&n);

	printf("\n结果为：%d", CountPath(m,n));
	}

	return 0;
}

