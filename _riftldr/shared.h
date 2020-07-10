/* This File is shared between multiple Projects and provides intercompatibility between them. */
#pragma once

/* Windows Naming Convention */
#define INLINE     __inline
#define STATIC       static
#define FASTCALL   __fastcall
#define DEPRECATED __declspec(deprecated)
typedef UUID*        PUUID;
typedef UUID         MD5, * PMD5;

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
#define CON_QUEST   ((FOREGROUND_BLUE) | FOREGROUND_INTENSITY)                   // 0b1001
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE  0x10                                                 // 128-Bit
#define AES_BLOB_SIZE (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)
#define MD5_SIZE      0x10                                                 // 128-Bit

// Crypto Information Block : Data Structer for Crypto and Hashing
typedef struct _CIB {
	BCRYPT_ALG_HANDLE ah;      // Algorithm Provider Handle
	union {                    // Algorithm dependend Handle
		BCRYPT_KEY_HANDLE  kh;  // Aes Key Handle (AES Algorithm)
		BCRYPT_HASH_HANDLE hh;  // Md5 Hash Handle (MD5 Algorithm)
	} uHandle;
	PVOID  pObj; // Allocated Object Address
	SIZE_T nObj; // Size of allocated Object
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
	BYTE Key[8 + AES_KEY_SIZE]; // Wrapped Aes128 Key (ew, hardcoded size that is not specified by BCrypt's docs (also fuck BCrypt's docs))
	BYTE Iv[16];                // Initialization-Vector
	MD5  Md5;                   // Md5-Checksum of original File
	BYTE Data[];                // Start of encrypted Data
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
#ifndef _riftTool
	HMODULE hMH;             // Current Module (BaseAddress)
	WCHAR   szMFN[MAX_PATH]; // Current Module Filename
	struct {                 // Hardware and Session ID's
		UUID HW;              // Hardware ID (linked to specific SMBIOS Entries)
		UUID SE;              // Session ID (linked to ACPI, FIRM and SMBIOS Information)
	} sID;
	struct {    // Standart Crypto Providers and Key's
		CIB SK;  // Internal deobfuscation Key (used to decrypt .WK and strings, maybe more in the future)
		CIB WK;  // Module decryption Key (used to unwrap the resources specific Key)
	} sCIB;
	struct {      // Commandline
		SIZE_T n;  // Number of elements inside the Vector
		PWSTR  v;  // Argument array (Vector)
	} sArg;
#endif
	WCHAR   szCD[MAX_PATH]; // Current Directory
	HANDLE  hPH;            // Process Heap Handle
} PIB, * PPIB;
EXTERN_C PPIB g_PIB;