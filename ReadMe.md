# AMBiPay Source Code
## Main Files
1. The 2-party adaptor signature schemes (Schnorr-based, ECDSA-based, and BLS-based) are implemented in 2pas.h and 2pas.cpp.
2. The ECDSA-based OVTS (Optimized Verifiable Timed Signatures) scheme is implemented in ovts.h and ovts.cpp.
3. The Pallier encryption scheme is implemented in pallier.h and pallier.cpp.
4. The ECDSA scheme is implemented in ecdsa.h and ecdsa.cpp.
5. The BLS scheme is implemented in bls.h and bls.cpp.

## Testing Files
1. The 2-party adaptor signature schemes (Schnorr-based, ECDSA-based, and BLS-based) are tested in 2pas_test.h and 2pas_test.cpp.
2. The ECDSA-based OVTS scheme is tested in ovts_test.h and ovts_test.cpp.
3. The Pallier encryption scheme is tested in pallier_test.h and pallier_test.cpp.
4. The ECDSA scheme is tested in ecdsa_test.h and ecdsa_test.cpp.
5. The BLS scheme is tested in bls_test.h and bls_test.cpp.

# Implementation Environment
The above schemes were implemented in C++ on a personal computer (PC). Our PC is configured with the Windows 10 operating system (64-bit) and equipped with an Intel(R) Core(TM) i7-9750H CPU with a clock speed of 2.60 GHz and 16 GB of RAM. The employed cryptographic library is Miracl V7.0 with the chosen standard NIST curve secp256k1 and BLS curve
(ate pairing embedding degree 24), both of which are with 256 bits security level.
