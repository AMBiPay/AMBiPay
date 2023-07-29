#include "ovts.h"



void CommitProve(miracl *mip, ovtsSysPara opara, ecdsaSig ecdsaSig, paiPriKey sk, ovtsX &ox, ovtsW &ow, ovtsPi &opi)
{
	Big tmpa, tmpn, tmpc;
	Big c1, c2, nlambda, BMod;
	ow.ws = ecdsaSig.s;
	ow.walpha = rand(opara.n >> 3) + 1;       // randomly choose r from [1, N]
	ow.wlambda = sk.lambda;
	ow.wr1 = rand(opara.q >> 3) + 1;
	ow.wr2 = rand(opara.q >> 3) + 1;
	ow.wr3 = rand(opara.q >> 3) + 1;
	/*
	modulo(opara.n2);
	tmpa = nres(ow.walpha); // initialize Montgomery context for modulus
	tmpn = nres(opara.n+1); // initialize Montgomery context for modulus	
	tmpc = nres_pow2(tmpn, ow.ws, tmpa, opara.n);
	ox.xct = redc(tmpc);
	*/

	BMod = get_modulus();
	ox.xct = pow(opara.n + 1, ow.ws, ow.walpha, opara.n, opara.n2);
	ox.ixct = inverse(ox.xct, opara.n2);
	
	nlambda = opara.n * ow.wlambda;
	ow.wbeta = rand(opara.q);       // randomly choose r from [1, N]
	ox.xu = pow(opara.g, ow.wbeta, opara.n);
	ox.ixu = inverse(ox.xu, opara.n);
	   
	ox.xv = pow(opara.h, opara.n*ow.wbeta, 1 + opara.n, ow.wlambda, opara.n2);	
	ox.ixv = inverse(ox.xv, opara.n2);
	
	ox.xR = pow(ow.walpha, 1, ox.xg1, ow.wr1, opara.n);
	ox.ixR = inverse(ox.xR, opara.n);
	modulo(BMod);

	ox.xR1 = mul(ow.wr1, ox.xG2, ow.wr2, ox.xH2);
	ox.xR2 = mul(nlambda % opara.q, ox.xG2, ow.wr3, ox.xH2);

	ow.wdelta = nlambda * ow.wr1;
	ow.wphi = nlambda * ow.wr2;
	
	NIZKProve(mip, opara, ox, ow, opi);
}


void NIZKProve(miracl *mip, ovtsSysPara opara, ovtsX ox, ovtsW ow, ovtsPi &opi)
{
	Big tmpa, tmpn, tmpc;
	Big ls, lbeta, llambda, lr1, lr2, lr3, ldelta, lphi, lalpha;
	Big Tct, Tu, Tv, TR, T1;
	ECn TK, TR1, TR2, T2, TMP;
	Big tmpx, tmpy, BMod, tmp, nlambda, qn;
	ls = rand(opara.q >> 3) + 1;
	lbeta = rand(opara.q >> 3) + 1;
	llambda = rand(opara.q >> 3) + 1;
	lr1 = rand(opara.q >> 3) + 1;
	lr2 = rand(opara.q >> 3) + 1;
	lr3 = rand(opara.q >> 3) + 1;
	ldelta = rand(opara.q >> 3) + 1;
	lphi = rand(opara.q >> 3) + 1;
	lalpha = rand(opara.q >> 3) + 1;
	nlambda = opara.n * llambda;
	qn = opara.q * opara.n;


	BMod = get_modulus();
	Tct = pow(1+opara.n, ls, lalpha, opara.n, opara.n2);
	
	Tu = pow(opara.g, lbeta, opara.n);
	Tv = pow(opara.h, opara.n*lbeta, 1 + opara.n, llambda, opara.n2);
	TR = pow(lalpha, 1, ox.xg1, lr1, opara.n);	
	modulo(BMod);


	BMod = get_modulus();
	tmp = pow(ox.ixg1, ldelta, opara.n2);
	T1 = pow(ox.xR, nlambda, tmp, 1, opara.n2);
	modulo(BMod);


	TR1 = mul(lr1, ox.xG2, lr2, ox.xH2);

	TR2 = mul(nlambda % opara.q, ox.xG2, lr3, ox.xH2);

	T2 = mul(nlambda % opara.q, ox.xR1, opara.q - ldelta, ox.xG2);
	TMP = ox.xH2;	
	TMP *= opara.q - lphi;
	T2 += TMP;	

	TK = ox.xK;
	TK *= ls;

	pfc.start_hash();
	pfc.add_to_hash(ox.xn);
	pfc.add_to_hash(ox.xg);
	pfc.add_to_hash(ox.xh);
	pfc.add_to_hash(ox.xct);
	pfc.add_to_hash(ox.xu);
	pfc.add_to_hash(ox.xv);
	pfc.add_to_hash(ox.xr);
	ox.xK.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xHm);
	ox.xG.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xP.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xR);
	ox.xR1.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xR2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xg1);
	ox.xG2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xH2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	pfc.add_to_hash(Tct);
	pfc.add_to_hash(Tu);
	pfc.add_to_hash(Tv);
	pfc.add_to_hash(TR);

	TR1.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	TR2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(T1);

	T2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	TK.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	opi.c = pfc.finish_hash_to_group();
	opi.c = opi.c;

	tmp = modmult(ow.ws, opi.c, qn);
	opi.zs = (ls + tmp) % qn;

	BMod = get_modulus();
	tmp = pow(ow.walpha, opi.c, qn);
	opi.zalpha = modmult(lalpha, tmp, qn);
	modulo(BMod);

	tmp = modmult(ow.wbeta, opi.c, qn);
	opi.zbeta = (lbeta + tmp) % qn;

	//tmp = modmult(ow.wlambda, opi.c, qn);
	opi.zlambda = (llambda + ow.wlambda * opi.c);
	
	tmp = modmult(ow.wr1, opi.c, qn);
	opi.zr1 = (lr1 + tmp) % qn;

	tmp = modmult(ow.wr2, opi.c, opara.q);
	opi.zr2 = (lr2 + tmp) % opara.q;

	tmp = modmult(ow.wr3, opi.c, opara.q);
	opi.zr3 = (lr3 + tmp) % opara.q;

	//tmp = modmult(ow.wdelta, opi.c, qn);
	opi.zdelta = ldelta + ow.wdelta * opi.c;

	tmp = modmult(ow.wphi, opi.c, opara.q);
	opi.zphi = (lphi + tmp) % opara.q;
	/*
	cout << "------------Prove--------------" << endl;
	cout << "Tct = " << Tct << endl;
	cout << "Tu = " << Tu << endl;
	cout << "Tv = " << Tv << endl;
	cout << "TR = " << TR << endl;
	cout << "TR1 = " << TR1 << endl;
	cout << "TR2 = " << TR2 << endl;
	cout << "T1 = " << T1 << endl;
	cout << "T2 = " << T2 << endl;
	cout << "TK = " << TK << endl;
	*/

}

int NIZKVerf(miracl *mip, ovtsSysPara opara, ECn PK, ovtsX ox, ovtsPi opi)
{
	Big Tct, Tu, Tv, TR, T1;
	ECn TK, TMP, TR1, TR2, T2;
	Big BMod, tmpc, tmpx, tmpy, nzlambda;
	
	BMod = get_modulus();
	Tct = pow(1 + opara.n, opi.zs, opi.zalpha, opara.n, opara.n2);
	Tct = pow(Tct, Big(1), ox.ixct, opi.c, opara.n2);
	Tu = pow(opara.g, opi.zbeta, ox.ixu, opi.c, opara.n);
	Tv = pow(opara.h, opara.n*opi.zbeta, 1 + opara.n, opi.zlambda, opara.n2);
	Tv = pow(Tv, Big(1), ox.ixv, opi.c, opara.n2);
	TR = pow(opi.zalpha, 1, ox.xg1, opi.zr1, opara.n);
	TR = pow(TR, 1, ox.ixR, opi.c, opara.n);
	modulo(BMod);


	TR1 = mul(opi.zr1, ox.xG2, opi.zr2, ox.xH2);
	TMP = ox.xR1;
	TMP *= (opara.q - opi.c);
	TR1 += TMP;


	TR2 = mul(opara.n * opi.zlambda, ox.xG2, opi.zr3, ox.xH2);
	TMP = ox.xR2;
	TMP *= (opara.q - opi.c);
	TR2 += TMP;

	nzlambda = opara.n * opi.zlambda;

	BMod = get_modulus();
	T1 = pow(ox.xR, nzlambda, ox.ixg1, opi.zdelta, opara.n2);
	modulo(BMod);


	T2 = mul(nzlambda, ox.xR1, opara.q - opi.zdelta, ox.xG2);
	TMP = ox.xH2;
	TMP *= (opara.q - opi.zphi);
	T2 += TMP;
	
	TMP = mul(ox.xHm, opara.G, ox.xr, PK);
	TK = mul(opi.zs, ox.xK, opara.q - opi.c, TMP);
	/*
	cout << "------------Verf--------------" << endl;
	cout << "Tct = " << Tct << endl;
	cout << "Tu = " << Tu << endl;
	cout << "Tv = " << Tv << endl;
	cout << "TR = " << TR << endl;
	cout << "TR1 = " << TR1 << endl;
	cout << "TR2 = " << TR2 << endl;
	cout << "T1 = " << T1 << endl;
	cout << "T2 = " << T2 << endl;
	cout << "TK = " << TK << endl;
	*/
	pfc.start_hash();
	pfc.start_hash();
	pfc.add_to_hash(ox.xn);
	pfc.add_to_hash(ox.xg);
	pfc.add_to_hash(ox.xh);
	pfc.add_to_hash(ox.xct);
	pfc.add_to_hash(ox.xu);
	pfc.add_to_hash(ox.xv);
	pfc.add_to_hash(ox.xr);
	ox.xK.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xHm);
	ox.xG.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xP.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xR);
	ox.xR1.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xR2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(ox.xg1);
	ox.xG2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	ox.xH2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	pfc.add_to_hash(Tct);
	pfc.add_to_hash(Tu);
	pfc.add_to_hash(Tv);
	pfc.add_to_hash(TR);

	TR1.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	
	TR2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);
	pfc.add_to_hash(T1);

	T2.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	TK.getxy(tmpx, tmpy);
	pfc.add_to_hash(tmpx);
	pfc.add_to_hash(tmpy);

	tmpc = pfc.finish_hash_to_group();

	if (tmpc == opi.c)
		return 1;
	else return 0;
}