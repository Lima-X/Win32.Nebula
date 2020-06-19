/* This File is shared between multiple Projects and provides intercompatibility between them. */
#pragma once
/* Compiler / Headers */
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* Windows Naming Convention */
#define INLINE __inline
#define STATIC static

/* Tpyedefs */
#if defined(_WIN32)
typedef unsigned long PTR;
#elif defined(_WIN64)
typedef unsigned long long PTR;
#endif

/* Process Information Block (replacment for Global Data) */
typedef struct {
#ifndef _riftCrypt
	HMODULE hMH;
	WCHAR szMFN[MAX_PATH];
#endif
	HANDLE hPH;
	WCHAR szCD[MAX_PATH];
} PIB, * PPIB;
PPIB g_PIB;

/* NoCRT / this provides replacement Macros for WinAPI Functions that rely on the CRT */
#undef CopyMemory
#define CopyMemory(dest, src, size)  __movsb(dest, src, size)
#undef ZeroMemory
#define ZeroMemory(dest, size)       __stosb(dest, 0, size)
#define SetMemory(dest, data, size)  __stosb(dest, data, size)

#define AllocMemory(cbBytes)         HeapAlloc(g_PIB->hPH, 0, cbBytes)
#define ReAllocMemory(pMem, cbBytes) HeapReAlloc(g_PIB->hPH, 0, pMem, cbBytes)
#define FreeMemory(pMem)             HeapFree(g_PIB->hPH, 0, pMem)

/* Console */
#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_INFO    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)        // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE  0x10                                                 // 128-Bit
#define AES_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)
#define MD5_SIZE      0x10                                                 // 128-Bit

BOOL EAesCryptBegin();
BOOL IAesLoadWKey(_In_ PVOID pWAes);
VOID EAesCryptEnd();
PVOID EUnpackResource(_In_ WORD wResID, _Out_ PSIZE_T nData);

BOOL EMd5HashBegin();
VOID EMd5HashEnd();
VOID EMd5HashData(_Out_ PVOID pMd5, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
BOOL EMd5Compare(_In_ PVOID pMD51, _In_ PVOID pMD52);

BOOL EDecompressBegin();
VOID EDecompressEnd();

// BCrypt Information Block : Data Structer for encryption and Hashing
typedef struct {
	BCRYPT_ALG_HANDLE ah;
	union {
		BCRYPT_KEY_HANDLE  kh;
		BCRYPT_HASH_HANDLE hh;
	};
	PVOID  pObj;
	SIZE_T nObj;
} CIB, * PCIB;

// Encrypted File/Resource Header
// This will probably be replaced with a dynamic header
typedef struct {
	BYTE KEY[8 + AES_KEY_SIZE]; // ew, hardcoded size that is not specified by BCrypt's docs
	BYTE IV[16];
	BYTE MD5[16];
	/* DATA */
} AESEX, * PAESEX;

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

/* Base64 Encoder/Decoder : Base64.c */
PBYTE EBase64Decode(_In_ PBYTE pBuffer, _In_ SIZE_T nBuffer, _Out_ PSIZE_T nResult);

/* Utilities and Other : Utils.c */
PDWORD EGetProcessIdbyName(_In_ PCWSTR pProcessName, _Out_ PSIZE_T nProcesses);