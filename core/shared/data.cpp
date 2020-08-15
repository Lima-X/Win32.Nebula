#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftdll
#include "..\_riftdll\_riftdll.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Global Process Information Block
PIB* g_PIB;

/* Contains the expected Hash of Section in the Image.
   This is only a Signature and has to be patched out with _riftTool. */
const cry::Md5::hash e_HashSig = *(cry::Md5::hash*)&".SectionHashSig";

#if 0 // Obsolete
const CHAR e_pszSections[][8] = {
	".rdata\0",   // Special
	// ".rsrc\0\0",  // Ignore
	// ".reloc\0"    // Ignore (not sure if UpdateResource might mess with this)
};
const size_t e_nSections = sizeof(e_pszSections) / sizeof(*e_pszSections);
#endif

/* The Current AesInternalKey used to decrypt Internal Data,
   this Key is hardcoded and should not be changed.
   Changing this Key would requirer to reencrypt all Data that is based on this Key,
   this includes all obfuscated Strings and even external Resources. */
const byte e_IKey[AES_KEY_SIZE] = {
	0xd9, 0xbf, 0x99, 0x27, 0x18, 0xca, 0x6a, 0xf6,
	0xb4, 0xd5, 0xd4, 0x67,	0x4e, 0xf5, 0xf9, 0x01
};
// KillSwitch Data Hash
DEPRECATED const byte e_KillSwitchHash[sizeof(cry::Md5::hash)] = {
	0xc5, 0xc9, 0x2b, 0x4e, 0xe2, 0xc4, 0x61, 0x8f,
	0x65, 0x59, 0xf1, 0x98, 0x48, 0xae, 0xf5, 0x3b
};