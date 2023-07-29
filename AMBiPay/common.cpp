
#include "common.h"
#include <stdio.h>
#include <iostream>

using namespace std;


Miracl precision(2050, 0);
miracl *mip = &precision;
PFC pfc(AES_SECURITY);  //Change the oreder of PFC and Miracl if facing with the error of number too big

void bytePrint(BYTE *source, int len)
{
	
	int i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%02X", source[i]);
	}
	printf("\n");
}

void byteXOR(BYTE *source1, BYTE *source2, BYTE *output, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		output[i] = source1[i] ^ source2[i];
	}
}

void byteCopy(BYTE *dest, int destBegin, BYTE *source, int sourceBegin, int copylen)
{
	int i = 0;
	for (i = 0; i < copylen; i++)
	{
		dest[i + destBegin] = source[i + sourceBegin];
	}
}

void GPrint(ECn G)
{
	Big x, y;
	G.getxy(x, y);
	cout << x << endl;
	cout << y << endl;
}

void byteReset(BYTE *dest, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		dest[i] = 0x0;
	}
}

/**********************************************************************************************
Description:  change char array to BYTE array
Input:  pCharBuf candiate char array
      charLen   length of char array
Output:  pByteBuf  output BYTE array 
	  byteLen   length of BYTE array
Return: 1: if change successfully
		0: otherwise
**********************************************************************************************/
int charToByte(char * pCharBuf, int charLen, BYTE * pByteBuf, int &byteLen)
{
	int tmpLen = 0;
	int i;
	BYTE lChar;
	BYTE hChar;

	tmpLen = charLen;
	if (tmpLen & LSBOfWord)
	{
		tmpLen += 1;
		byteLen = tmpLen >> 1;
		if (ConvertHexChar(pCharBuf[0], lChar) == 1)
		{
			pByteBuf[0] = lChar;
		}
		for (i = 1; i < byteLen; i++)
		{
			if (ConvertHexChar(pCharBuf[2 * i - 1], hChar) == 1)
			{
				if (ConvertHexChar(pCharBuf[2 * i], lChar) == 1)
				{
					pByteBuf[i] = (hChar << 4) | lChar;
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
	}
	else
	{
		byteLen = tmpLen >> 1;
		for (i = 0; i < byteLen; i++)
		{
			if (ConvertHexChar(pCharBuf[2 * i], hChar) == 1)
			{
				if (ConvertHexChar(pCharBuf[2 * i + 1], lChar) == 1)
				{
					pByteBuf[i] = (hChar << 4) | lChar;
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
	}
	return 1;
}


/**********************************************************************************************
Description: change char to HEX element stored as BYTE
Input: ch: candiate char
Output: ch_byte: element of Byte type
return: 1: change successfully,
		0: otherwise
**********************************************************************************************/
int ConvertHexChar(char ch, BYTE &ch_byte)
{
	if ((ch >= '0') && (ch <= '9'))
	{

		ch_byte = (BYTE)(ch - 0x30);
		return 1;

	}
	else
	{
		if ((ch >= 'A') && (ch <= 'F'))
		{
			ch_byte = (BYTE)(ch - 'A' + 0x0a);
			return 1;
		}
		else
		{
			if ((ch >= 'a') && (ch <= 'f'))
			{
				ch_byte = (BYTE)(ch - 'a' + 0x0a);
				return 1;
			}
		}
	}
	return 0;
}

/**********************************************************************************************
Description: change BYTE array to G1 element
Input: input: candiate BYTE array
Output: g1: output G1 element
**********************************************************************************************/
void byteToG1(BYTE *input, G1 &g1)
{
	Big xG, yG;
	ECn tmpG;

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)input);
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + PFC_BYTELEN_PER_BIG));

	if (!tmpG.set(xG, yG))
	{
		cout << "Not a G1" << endl;
	}
	g1.mtable = NULL;
	g1.mtbits = 0;
	g1.g.set(xG, yG);
}

/**********************************************************************************************
Description: change G1 to BYTE array
Input: g1: candiate G1 element
Output: output: BYTE array
**********************************************************************************************/
void g1ToByte(G1 g1, BYTE *output)
{
	Big xG, yG;

	g1.g.get(xG, yG);

	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)output, true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + PFC_BYTELEN_PER_BIG), true);
}

/**********************************************************************************************
Description: print G1 element
Input: g1: G1 element
**********************************************************************************************/
void G1Print(G1 g1)
{
	Big xG, yG;
	g1.g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
}

/**********************************************************************************************
Description: change BYTE array to G2 element
Input: input: candiate Byte array
Output: g2: G2 element
**********************************************************************************************/
void byteToG2(BYTE *input, G2 &g2)
{
	Big xG, yG;
	ZZn4 a, b;
	ZZn2 c, d;
	

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)input);
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + PFC_BYTELEN_PER_BIG));
	c.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 2 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 3 * PFC_BYTELEN_PER_BIG));
	d.set(xG, yG);
	a.set(c, d);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 4 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 5 * PFC_BYTELEN_PER_BIG));
	c.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 6 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 7 * PFC_BYTELEN_PER_BIG));
	d.set(xG, yG);
	b.set(c, d);

	g2.ptable = NULL;
	g2.mtable = NULL;
	g2.mtbits = 0;
	g2.g.set(a, b);
}

/**********************************************************************************************
Description: print G2 element
Input: g2: G2 element
**********************************************************************************************/
void G2Print(G2 g2)
{
	Big xG, yG;
	ZZn4 a, b;
	ZZn2 c, d;


	g2.g.get(a, b);

	a.get(c, d);
	c.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	d.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	b.get(c, d);
	c.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	d.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
}

/**********************************************************************************************
Description: change G2 to BYTE array
Input: g2: candiate G2 element
Output: output: BYTE array
**********************************************************************************************/
void g2ToByte(G2 g2, BYTE *output)
{
	Big xG, yG;
	ZZn4 a, b;
	ZZn2 c, d;

	g2.g.get(a, b);
	a.get(c, d);
	c.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)output, true);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + PFC_BYTELEN_PER_BIG), true);

	d.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 2 * PFC_BYTELEN_PER_BIG), true);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 3 * PFC_BYTELEN_PER_BIG), true);

	b.get(c, d);
	c.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 4 * PFC_BYTELEN_PER_BIG), true);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 5 * PFC_BYTELEN_PER_BIG), true);

	d.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 6 * PFC_BYTELEN_PER_BIG), true);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 7 * PFC_BYTELEN_PER_BIG), true);

}


/**********************************************************************************************
Description: change BYTE array to GT element
Input: input: candiate BYTE array
Output: gt: GT element
**********************************************************************************************/
void byteToGT(BYTE *input, GT &gt)
{
	ZZn8 a, b, c;
	ZZn4 d, e;
	ZZn2 f, g;
	Big xG, yG;

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)input);
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input+PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 2 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 3 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	d.set(f, g);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 4 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 5 * PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 6 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 7 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	e.set(f, g);
	a.set(d, e);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 8 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 9 * PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 10 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 11 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	d.set(f, g);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 12 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 13 * PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 14 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 15 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	e.set(f, g);
	b.set(d, e);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 16 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 17 * PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 18 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 19 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	d.set(f, g);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 20 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 21 * PFC_BYTELEN_PER_BIG));
	f.set(xG, yG);

	xG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 22 * PFC_BYTELEN_PER_BIG));
	yG = from_binary(PFC_BYTELEN_PER_BIG, (char *)(input + 23 * PFC_BYTELEN_PER_BIG));
	g.set(xG, yG);
	e.set(f, g);
	c.set(d, e);

	gt.etable = NULL;
	gt.etbits = 0;
	gt.g.set(a, b, c);
}

/**********************************************************************************************
Description: print GT element
Input: gt: GT element
**********************************************************************************************/
void GTPrint(GT gt)
{
	ZZn8 a, b, c;
	ZZn4 d, e;
	ZZn2 f, g;
	Big xG, yG;

	gt.g.get(a, b, c);

	a.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	e.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	b.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	e.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	c.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;

	e.get(f, g);
	f.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
	g.get(xG, yG);
	cout << xG << endl;
	cout << yG << endl;
}

/**********************************************************************************************
Description: change GT to BYTE array
Input: gt: candiate GT element
Output: output: BYTE array
**********************************************************************************************/
void gtToByte(GT gt, BYTE *output)
{
	ZZn8 a, b, c;
	ZZn4 d, e;
	ZZn2 f, g;
	Big xG, yG;
	gt.g.get(a, b, c);

	a.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)output, true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 2 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 3 * PFC_BYTELEN_PER_BIG), true);

	e.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 4 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 5 * PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 6 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 7 * PFC_BYTELEN_PER_BIG), true);

	b.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 8 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 9 * PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 10 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 11 * PFC_BYTELEN_PER_BIG), true);

	e.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 12 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 13 * PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 14 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 15 * PFC_BYTELEN_PER_BIG), true);

	c.get(d, e);
	d.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 16 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 17 * PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 18 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 19 * PFC_BYTELEN_PER_BIG), true);

	e.get(f, g);
	f.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 20 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 21 * PFC_BYTELEN_PER_BIG), true);
	g.get(xG, yG);
	to_binary(xG, PFC_BYTELEN_PER_BIG, (char *)(output + 22 * PFC_BYTELEN_PER_BIG), true);
	to_binary(yG, PFC_BYTELEN_PER_BIG, (char *)(output + 23 * PFC_BYTELEN_PER_BIG), true);
}