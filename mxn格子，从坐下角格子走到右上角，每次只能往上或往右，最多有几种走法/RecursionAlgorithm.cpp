// RecursionAlgorithm.cpp : �������̨Ӧ�ó������ڵ㡣
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

	printf("========================\n��������m:");
	scanf("%d", &m);
	printf("\n��������n:");
	scanf("%d",&n);

	printf("\n���Ϊ��%d", CountPath(m,n));
	}

	return 0;
}

