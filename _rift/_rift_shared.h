#pragma once
#ifndef _shared_HIG
#define _shared_HIG
#include "config.h"

/* BCrypt */
typedef struct {
	BYTE  KEY[(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) - 4) + 32];
	BYTE  WRAP[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 32];
	BYTE  IV[16];
	DWORD CRC;
} AESKEY, * PAESKEY;

/* CRC32 Hash-Algorithm : CRC32.c */
DWORD fnCRC32(_In_ PBYTE pBuffer, _In_ SIZE_T nBufferLen);
VOID fnAllocTable();
VOID fnFreeTable();
HANDLE g_hPH;

/* Xoshiro PRNG Algorithm : Xoshiro.c */
typedef struct {
#if _DISABLE_JUMPS == 0
	DWORD ran : 3;
	DWORD lj : 8;
	DWORD sj : 8;
	DWORD ns : 13;
#else
	WORD ran : 3;
	WORD ns : 13;
#endif
} XSR, * PXSR;

#endif // !_shared_HIG