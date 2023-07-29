#include "paillier.h"

void paillKGen(miracl *mip, int secPara, paiPubKey &pk, paiPriKey &sk)
{

	sk.p = rand(secPara, 2);
	if (sk.p % 2 == 0)
	{
		sk.p += 1;
	}
	while (prime(sk.p) == 0)		// find a big prime from the odd
	{
		sk.p += 2;
	}

	sk.q = rand(secPara, 2);
	if (sk.q % 2 == 0)
	{
		sk.q += 1;
	}
	while (prime(sk.q) == 0)	   // find a big prime from the odd
	{
		sk.q += 2;
	}
	pk.N = sk.p * sk.q;				// n = p*q
	pk.N2 = pk.N * pk.N;			//n2 = n*n

	pk.g = pk.N + 1;				// g = n+1
	sk.lambda = (sk.p - 1) * (sk.q - 1);   // lambda = (p-1)(q-1)
	sk.mu = inverse(sk.lambda, pk.N);  // mu = lambda ^{-1} mod n
}

void paillKGen(miracl *mip, int secPara, Big ecn, paiPubKey &pk, paiPriKey &sk)
{
	Big pq, tmpg;
	
	sk.p = rand(secPara, 2);
	if (sk.p % 2 == 0)
	{
		sk.p += 1;
	}
	
	while (prime(sk.p) == 0 || gcd(ecn, sk.p - 1) != 1)		// find a big prime from the odd
	{
		sk.p += 2;
	}

	sk.q = rand(secPara, 2);
	if (sk.q % 2 == 0)
	{
		sk.q += 1;
	}
	while (prime(sk.q) == 0 || gcd(ecn, sk.q - 1) != 1)	   // find a big prime from the odd
	{
		sk.q += 2;
	}

	pq = sk.p * sk.q;
	pk.N = pq * ecn;			    // n = ecn*p*q
	pk.N2 = pk.N * pk.N;			//n2 = n*n

	tmpg = pk.N + 1;				// tmpg = n+1
	pk.g = pow(tmpg, pq, pk.N2);    // g = tmpg ^{pq} mod N^2
	sk.lambda = (sk.p - 1) * (sk.q - 1);   
	sk.lambda *= ecn - 1;				  // lambda = (ecn-1)(p-1)(q-1)
	sk.mu = inverse(sk.lambda, ecn);  // mu = lambda ^{-1} mod n
}


void paillEnc(miracl *mip, paiPubKey pk, Big msg, Big &cipher)
{
	Big r;
	Big c1, c2;
	r = rand(pk.N2);       // randomly choose r from [1, N^2]
//	c1 = pow(pk.g, msg, pk.N2);
//	c2 = pow(r, pk.N, pk.N2);
//	cipher = modmult(c1, c2, pk.N2) ;
	cipher = pow(pk.g, msg, r, pk.N, pk.N2);
}

void paillEncMont(miracl *mip, paiPubKey pk, Big msg, Big &cipher)
{
	
	Big r, tmpr, tmpg, tmpc;
	Big c1, c2;
	r = rand(pk.N2);       // randomly choose r from [1, N^2]

	modulo(pk.N2);
	tmpr = nres(r); // initialize Montgomery context for modulus
	tmpg = nres(pk.g); // initialize Montgomery context for modulus	
	tmpc = nres_pow2(tmpg, msg, tmpr, pk.N);
	cipher = redc(tmpc);
}
void paillDecMont(miracl *mip, paiPriKey sk, paiPubKey pk, Big cipher, Big &msg)
{
	Big tmpc, tmpc1, tmpc2, tmpc3, tmpcipher, tmpmsg, tmpmu;
	modulo(pk.N2);
	tmpcipher = nres(cipher);
	tmpc = nres_pow(tmpcipher, sk.lambda);   // tmpc = c^{\lambda} mod N^2
	tmpc = redc(tmpc);
	tmpc2 = (tmpc - 1) / pk.N;				// tmpc1 = (tmpc-1)/N
	modulo(pk.N);
	tmpmu = nres(sk.mu);
	tmpc2 = nres(tmpc2);
	tmpmsg = nres_modmult(tmpc2, tmpmu);				// msg = tmpc1 * mu mod N
	msg = redc(tmpmsg);
}

void paillDec(miracl *mip, paiPriKey sk, paiPubKey pk, Big cipher, Big &msg)
{
	Big tmpc, tmpc1;
	tmpc = pow(cipher, sk.lambda, pk.N2);   // tmpc = c^{\lambda} mod N^2
	tmpc1 = (tmpc - 1) / pk.N;				// tmpc1 = (tmpc-1)/N
	msg = tmpc1 * sk.mu % pk.N;				// msg = tmpc1 * mu mod N
}


void paillDec(miracl *mip, paiPriKey sk, Big ecn, paiPubKey pk, Big cipher, Big &msg)
{
	Big npq;
	Big tmpc, tmpc1;
	tmpc = pow(cipher, sk.lambda, pk.N2);   // tmpc = c^{\lambda} mod N^2
	npq = pk.N * sk.p;
	npq *= sk.q;							// Npq  = N*p*q
	tmpc1 = (tmpc - 1) / npq;				// tmpc1 = (tmpc-1)/Npq
	msg = tmpc1 * sk.mu % ecn;				// msg = tmpc1 * mu mod N
}