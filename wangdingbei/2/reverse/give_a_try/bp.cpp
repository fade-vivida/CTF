#include <iostream>
#include <cstdio>
#include <cstdlib>

using namespace std;

unsigned int m[42] = 
{
	1683306, 2791044, 2305108, 2970108, 

	16728, 3588802, 2192320, 914940, 

	2437320, 459867, 2875365, 3571292, 

	3320616, 373422, 418836, 1584825, 

	634980, 2859675, 358545, 1535390, 

	724608, 929480, 1815345, 1152676, 

	1134546, 1584660, 670815, 1820736, 

	1900496, 106539, 877572, 679677, 

	233985, 1028790, 169282, 992560, 

	469568, 133570, 2957031, 460096, 

	2915374, 3752875

};

unsigned char flag[42] = {0};
int main(){
	unsigned int a = 0x31333359;
	for(unsigned i=0;i<0xff*42;i++)
	{
		srand(a^i);
		unsigned int sum = 0;
		for(int j=0;j<42;j++)
		{
			unsigned int b = rand();
			flag[j] = (m[j]/b)&0xff;
			sum += flag[j];
		}
		if(sum == i)
		{
			printf("%d\n",sum);
			for(int j=0;j<42;j++)
				printf("%c",flag[j]);
			printf("\n");
		}
	}
}
