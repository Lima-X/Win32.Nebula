/* This File is shared between multiple Projects and provides intercompatibility between them. */
#pragma once

/* Windows Naming Convention */
#define INLINE     __inline
#define STATIC       static
#define FASTCALL   __fastcall
#define DEPRECATED __declspec(deprecated)
#define EXTERN       EXTERN_C
typedef GUID*        PUUID;
typedef GUID         MD5, * PMD5;

/* Function Status return Value:
   x=0 if Successful
   x<0 if Failure (Errorcode)
   x>0 reserved for extra Info (also Success) */
typedef signed long STATUS;

// Raw Pointer Type
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
INLINE INT CompareMemory(
	_In_ PVOID  pMem1,
	_In_ PVOID  pMem2,
	_In_ SIZE_T nSize
) {
	PBYTE pMem1C = (PBYTE)pMem1, pMem2C = (PBYTE)pMem2;
	while (nSize--) {
		if (*pMem1C++ != *pMem2C++)
			return *--pMem1C < *--pMem2C ? -1 : 1;
	} return 0;
}

/* Console */
#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_INFO    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)        // 0b0111
#define CON_QUEST   ((FOREGROUND_BLUE) | FOREGROUND_INTENSITY)                   // 0b1001
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   ((FOREGROUND_RED) | FOREGROUND_INTENSITY)                    // 0b1100

/* BCrypt */
#define AES_KEY_SIZE    0x10                                                 // 128-Bit
#define AES_BLOB_SIZE   (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)
#define AES_WARPED_SIZE (8 + AES_KEY_SIZE)                                   // 24-Bytes (Hardcoded)

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

BOOL EMd5HashData(_In_ PVOID pBuffer, _In_ SIZE_T nBuffer, _Out_ PMD5 pHash);
// BOOL EMd5Compare(_In_ PVOID pMD51, _In_ PVOID pMD52);

// Encrypted File/Resource Header
typedef struct _AESIB {
	BYTE Key[AES_WARPED_SIZE]; // Wrapped Aes128 Key (ew, hardcoded size that is not specified by BCrypt's docs (also fuck BCrypt's docs))
	BYTE Iv[16];               // Initialization-Vector
	MD5  Md5;                  // Md5-Checksum of original File
	BYTE Data[];               // Start of encrypted Data
} AESIB, * PAESIB;

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

/* Base64 Encoder/Decoder, UUID Converters and SigScanner : shared.c */
// why -A suffix, because these functions work with raw data,
// also Hex and Base64 don't need Unicode
// and it would be stupid to use Unicode outside of the programm anyways,
// as it would just bloat the data
STATUS EBase64EncodeA(_In_ PVOID pData, _In_ SIZE_T nData, _Out_opt_ PSTR psz, _In_ PCSTR pTable, _In_ BOOLEAN bPad);
STATUS EBase64DecodeA(_In_ PCSTR  psz, _In_ SIZE_T nsz, _Out_opt_ PVOID pData, _In_ PUCHAR pTable);

#define UUID_STRLEN (16 * 2 + 4)
VOID EUuidEncodeA(_In_ PUUID pId, _Out_ PSTR pString);
VOID EUuidDecodeA(_In_  PCSTR pString, _Out_ PUUID pId);

typedef struct _SIG { // Signature Block
	PVOID  pSig;       // Signature
	PCSTR  szMask;     // Mask (to ignore certain Bytes)
	SIZE_T nLength;    // Length of Signature to search
} SIG, * PSIG;
PVOID ESigScan(_In_ PVOID pData, _In_ SIZE_T nData, _In_ PSIG sig);

/* Utilities and Other : Utils.c */
PDWORD EGetProcessIdbyName(_In_ PCWSTR pProcessName, _Out_ PSIZE_T nProcesses);

/* Process Information Block (replacment for Global Data) */
typedef struct _PIB {
	HANDLE  hPH; // Process Heap Handle
#ifndef _riftTool
	struct {     // Hardware and Session ID's
		UUID HW;  // Hardware ID (linked to specific SMBIOS Entries)
		UUID SE;  // Session ID (linked to ACPI, FIRM and SMBIOS Information)
	} sID;
	struct {    // Standart Crypto Providers and Key's
		CIB SK;  // Internal deobfuscation Key (used to decrypt .WK and strings, maybe more in the future)
		CIB WK;  // Module decryption Key (used to unwrap the resources specific Key)
	} sCIB;
	struct {      // Commandline
		SIZE_T n;  // Number of elements inside the Vector
		PWSTR* v;  // Argument array (Vector)
	} sArg;
#endif
	struct {                     // Module Information
		HMODULE hMH;              // Current Module (BaseAddress)
		WCHAR   szMFN[MAX_PATH];  // Current Module Filename
		WCHAR   szCD[MAX_PATH];   // Current Directory
	} sMod;
} PIB, * PPIB;
EXTERN PPIB g_PIB;