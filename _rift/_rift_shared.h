#pragma once
/* Compiler / Headers */
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma warning(disable : 4214)

/* Global Data */
HANDLE g_hPH;

/* Console */
#define CON_SUCCESS ((FOREGROUND_GREEN) | FOREGROUND_INTENSITY)                  // 0b0010
#define CON_INFO    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)        // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE 0x20                                                   // 256-Bits
#define AES_IV_SIZE 0x10                                                    // 128-Bits
#define WRAP_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 44-Bytes (Dynamic)
#define MD5_HASH_SIZE 0x10

typedef struct {
	BYTE  KEY[8 + AES_KEY_SIZE]; // ew, hardcoded size that is not specified by BCrypt's docs
	BYTE  IV[AES_IV_SIZE];
	DWORD CRC;                   // to be replaced with md5
	BYTE  MD5[MD5_HASH_SIZE];
} AESEX, * PAESEX;

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

/* CRC32 Hash-Algorithm : CRC32.c */
DWORD fnCRC32(_In_ PBYTE pBuffer, _In_ SIZE_T nBufferLen);
VOID  fnAllocTable();
VOID  fnFreeTable();

/* MD5 Hashing : Hash.c */
PVOID fnMD5HashData(
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
);

/* Xoshiro PRNG Algorithm : Xoshiro.c */
