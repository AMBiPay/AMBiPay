#include "paillier_test.h"
using namespace std;
#include <ctime>
#include<windows.h>

void paillEnc_test()
{
	Miracl precision(2050, 0);
	miracl *mip = &precision;
	LARGE_INTEGER freq;
	LARGE_INTEGER start_t, stop_t;
	double exe_time = 0;
	int secPara = 256;
	time_t seed;
	paiPubKey pk;
	paiPriKey sk;
	Big msg, msg1, cipher;
	int num = 10;
	mip->IOBASE = 16;
	time(&seed);
	irand((long)seed);   /* change parameter for different values */


	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		paillKGen(mip, secPara, pk, sk);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of KGen = " << exe_time / num << " ms" << endl;
	

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	msg = rand(pk.N);

	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		paillEncMont(mip, pk, msg, cipher);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of paillEncMont = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		paillDecMont(mip, sk, pk, cipher, msg1);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of paillDecMont = " << exe_time / num << " ms" << endl;

	if (msg == msg1)
	{
		cout << "Mont-Decrypt Successfully!" << endl;
	}
	else
	{
		cout << "False!" << endl;
	}

	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		paillEnc(mip, pk, msg, cipher);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Enc = " << exe_time / num << " ms" << endl;

	QueryPerformanceFrequency(&freq);// obtain clock frequency 
	exe_time = 0;
	for (int k = 0; k < num; k++)
	{
		QueryPerformanceCounter(&start_t);
		paillDec(mip, sk, pk, cipher, msg1);
		QueryPerformanceCounter(&stop_t);
		exe_time += 1e3*(stop_t.QuadPart - start_t.QuadPart) / freq.QuadPart;
	}
	cout << "The performance of Dec = " << exe_time / num << " ms" << endl;

	paillDec(mip, sk, pk, cipher, msg1);
	if (msg == msg1)
	{
		cout << "Decrypt Successfully!" << endl;
	}

	
}

void paillEnc1_test()
{
	BYTE *ecn = (BYTE *) "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
	Big n;
	int secPara = 256;
	time_t seed;
	paiPubKey pk;
	paiPriKey sk;
	Big msg, msg1, cipher;
	int num = 100;
	mip->IOBASE = 16;
	time(&seed);
	irand((long)seed);   /* change parameter for different values */
	
	n = Big((char *)ecn);
	for (int k = 0; k < num; k++)
	{
		paillKGen(mip, secPara, n, pk, sk);
		msg = rand(n);
		paillEnc(mip, pk, msg, cipher);
		paillDec(mip, sk, n, pk, cipher, msg1);
		if (msg == msg1)
		{
			cout << "Decrypt Successfully!" << endl;
		}
		else
		{
			cout << "Fails!" << endl;
			break;
		}

	}
}
