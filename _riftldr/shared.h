/* This File is shared between multiple Projects and provides intercompatibility between them. */
#pragma once

/* Windows Naming Convention */
#define INLINE     __inline
#define STATIC       static
#define FASTCALL   __fastcall
#define DEPRECATED __declspec(deprecated)
typedef UUID*        PUUID;

/* Typedefs */
#ifdef _WIN64
typedef unsigned long long PTR;
#elif _WIN32
typedef unsigned long      PTR;
#endif

/* NoCRT / this provides replacement Macros for WinAPI Functions that rely on the CRT */
#undef CopyMemory
#define CopyMemory(dest, src, size)  __movsb(dest, src, size)
#undef ZeroMemory
#define ZeroMemory(dest, size)       __stosb(dest, 0, size)
#define SetMemory(dest, data, size)  __stosb(dest, data, size)

#define AllocMemory(cbBytes)         HeapAlloc(g_PIB->hPH, NULL, cbBytes)
#define ReAllocMemory(pMem, cbBytes) HeapReAlloc(g_PIB->hPH, NULL, pMem, cbBytes)
#define FreeMemory(pMem)             HeapFree(g_PIB->hPH, NULL, pMem)

/* Console */
#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_INFO    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)        // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE  0x10                                                 // 128-Bit
#define AES_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)
#define MD5_SIZE      0x10                                                 // 128-Bit

// Crypto Information Block : Data Structer for encryption and Hashing
typedef struct _CIB {
	BCRYPT_ALG_HANDLE ah;
	union {
		BCRYPT_KEY_HANDLE  kh;
		BCRYPT_HASH_HANDLE hh;
	} uHandle;
	PVOID  pObj;
	SIZE_T nObj;
} CIB, * PCIB;

BOOL ECryptBegin(_In_ PVOID pBlob, _Out_ PCIB cib);
VOID ECryptEnd(_In_ PCIB cib);
PVOID EUnpackResource(_In_ PCIB cib, _In_ WORD wResID, _Out_ PSIZE_T nData);

PCWSTR EDecryptString(_In_ PCIB cib, _In_ PCSTR pString, _Out_ PSIZE_T nResult);
#define DecryptString(pString, nResult) EDecryptString(&g_PIB->sCIB.SK, pString, nResult)

PVOID EMd5HashData(_In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
BOOL EMd5Compare(_In_ PVOID pMD51, _In_ PVOID pMD52);

// Encrypted File/Resource Header
typedef struct _AESIB {
	BYTE Key[8 + AES_KEY_SIZE]; // ew, hardcoded size that is not specified by BCrypt's docs
	BYTE Iv[16];
	BYTE Md5[16];
	BYTE Data[];
} AESIB, * PAESIB;

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

/* Base64 Encoder/Decoder / UUID Converters : DataCoder.c */
PCSTR EBase64EncodeA(_In_ PVOID pData, _In_ SIZE_T nData, _Out_ PSIZE_T nOut);
PVOID EBase64DecodeA(_In_ PCSTR pString, _In_ SIZE_T nString, _Out_ PSIZE_T nOut);

/* Utilities and Other : Utils.c */
PDWORD EGetProcessIdbyName(_In_ PCWSTR pProcessName, _Out_ PSIZE_T nProcesses);

/* Process Information Block (replacment for Global Data) */
typedef struct _PIB {
#ifndef _riftCrypt
	HMODULE hMH;
	WCHAR   szMFN[MAX_PATH];
	struct {
		UUID HW;
		UUID SE;
	} sID;
	struct {
		CIB SK;
		CIB WK;
	} sCIB;
#endif
	HANDLE  hPH;
	WCHAR   szCD[MAX_PATH];
} PIB, * PPIB;
EXTERN_C PPIB g_PIB;