#ifdef _riftldr
#include "_riftldr.h"
#elif _riftdll
#include "..\_riftdll\_riftdll.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Global Process Information Block
PPIB g_PIB;

/* l_CSh (CodeSectionHash) contains the expected Hash of the CodeSection of the Image.
   This is only a Signature and has to be patched out with _riftTool. */
CONST BYTE e_HashSig[16] = { // == 128-Bit/16-Byte
	".SectionHashSig\0"
};
CONST CHAR e_pszSections[3][8] = {
	".rdata\0\0",  // Special
	".rsrc\0\0\0", // Ignore
	".reloc\0\0"   // Ignore (not sure if UpdateResource might mess with this)
};

// The Current AesStringKey used to decrypt Strings
CONST BYTE e_SKey[28] = {
	0x4B, 0x44, 0x42, 0x4D, 0x01, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00,	0xD9, 0xBF, 0x99, 0x27,
	0x18, 0xCA, 0x6A, 0xF6, 0xB4, 0xD5, 0xD4, 0x67,
	0x4E, 0xF5, 0xF9, 0x01
};

// Base64 Encoder/Decoder CharSet
CONST CHAR e_Base64Table[64] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
};