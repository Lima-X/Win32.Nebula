/* This File is shared between multiple Projects and provides intercompatibility between them.
   It */
#pragma once
/* Compiler / Headers */
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

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
#define CopyMemory(dest, src, size) __movsb(dest, src, size)
#undef ZeroMemory
#define ZeroMemory(dest, size) __stosb(dest, 0, size)

#define MSet(dest, data, size) __stosb(dest, data, size)
#define HAlloc(cbBytes, dwFlags) HeapAlloc(g_PIB->hPH, dwFlags, cbBytes)
#define HFree(pMem) HeapFree(g_PIB->hPH, 0, pMem)

/* Console */
#define CON_SUCCESS ((FOREGROUND_GREEN) | FOREGROUND_INTENSITY)                  // 0b0010
#define CON_INFO    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)        // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE 0x10                                                   // 128-Bit
#define AES_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)

PVOID fnUnpackResource(_In_ WORD wResID, _Out_ PSIZE_T nData);
VOID fnLoadWrapKey(_In_ PCWSTR szFileName);

typedef struct {
	BYTE KEY[8 + AES_KEY_SIZE]; // ew, hardcoded size that is not specified by BCrypt's docs
	BYTE IV[16];
	BYTE MD5[16];
	/* DATA */
} AESEX, * PAESEX;

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

/* MD5 Hashing : Hash.c */
PVOID fnMD5HashData(_In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
BOOL fnMD5Compare(_In_ PVOID pMD51, _In_ PVOID pMD52);

/* Base64 Encoder/Decoder : Base64.c */
extern CONST CHAR g_Base64Table[64];
PBYTE fnB64Encode(_In_ PBYTE pBuffer, _In_ SIZE_T nBuffer, _Out_ PSIZE_T nResult);
PBYTE fnB64Decode(_In_ PBYTE pBuffer, _In_ SIZE_T nBuffer, _Out_ PSIZE_T nResult);