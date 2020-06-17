#include "pch.h"
#ifdef _rift
#include "_rift.h"
#elif defined(_riftTool)
#include "..\_riftTool\_riftTool.h"
#endif

/* l_CSh (CodeSectionHash) contains the expected Hash of the CodeSection of the Image.
   This is only a Signature and has to be patched out with _riftTool. */
CONST BYTE e_HashSig[16] = { // == 128-Bit/16-Byte
	'.', 't', 'e', 'x', 't', 'M', 'd', '5', 'S', 'i', 'g', 0, 0, 0, 0, 0
};
CONST CHAR e_pszSections[3][8] = {
	{ '.', 'r', 'd', 'a', 't', 'a', 0, 0 }, // Special
	{ '.', 'r', 's', 'r', 'c', 0, 0, 0 },   // Ignore
	{ '.', 'r', 'e', 'l', 'o', 'c', 0, 0 }  // Ignore
};

// The Current AesStringKey used to decrypt Strings
CONST CHAR e_szB64StringKey[40] = { "S0RCTQEAAAAQAAAA2b+ZJxjKava01dRnTvX5AQ==" };

// Base64 Encoder/Decoder CharSet
CONST CHAR e_Base64Table[64] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
};