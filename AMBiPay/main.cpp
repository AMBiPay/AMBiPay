
#include "ecdsa_test.h"
#include "bls_test.h"
#include "paillier_test.h"
#include "2pas_test.h"
#include "ovts_test.h"

#include <stdio.h>
int main()
{
	bls2Sign_test();
	schnorr2Sign_test();
	CommitProve_test();
	ecdsa2Sign_test();
	
}