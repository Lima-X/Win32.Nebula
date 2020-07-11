#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftdll
#include "..\_riftdll\_riftdll.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Global Process Information Block
PPIB g_PIB;

/* l_CSh (CodeSectionHash) contains the expected Hash of the CodeSection of the Image.
   This is only a Signature and has to be patched out with _riftTool. */
CONST SIG e_HashSig2 = {
	".SectionHashSig",
	"xxxxxxxxxxxxxxxx",
	16
};



CONST CHAR e_pszSections[][8] = {
	".rdata\0",  // Special
	".rsrc\0\0", // Ignore
	// ".reloc\0"   // Ignore (not sure if UpdateResource might mess with this)
};
CONST SIZE_T e_nSections = sizeof(e_pszSections) / sizeof(*e_pszSections);

// The Current AesStringKey used to decrypt Strings
CONST BYTE e_SKey[16] = {
	0xD9, 0xBF, 0x99, 0x27,
	0x18, 0xCA, 0x6A, 0xF6,
	0xB4, 0xD5, 0xD4, 0x67,
	0x4E, 0xF5, 0xF9, 0x01
};

// Base64 Encoder/Decoder CharSet
CONST CHAR e_Base64Table[] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
};