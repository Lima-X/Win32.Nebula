#include "pch.h"
#include "_rift_shared.h"
#ifdef _rift
#include "_rift.h"
#endif

// BCrypt Information Block : Data Structer for encryption and Hashing
typedef struct {
	BCRYPT_ALG_HANDLE ah;
	union {
		BCRYPT_KEY_HANDLE  kh;
		BCRYPT_HASH_HANDLE hh;
	};
	PVOID  pObj;
	SIZE_T nObj;
} BCIB, * PBCIB;
PBCIB l_BCH[2];

/* These functions act as Constructors / Destructors,
   they manage internal data */
BOOL fnAesCryptBegin() {
	l_BCH[0] = AllocMemory(sizeof(BCIB), 0);
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&l_BCH[0]->ah, BCRYPT_AES_ALGORITHM, 0, 0);

	// Create KeyOBJ / Import Key
	SIZE_T nResult;
	nts = BCryptGetProperty(l_BCH[0]->ah, BCRYPT_OBJECT_LENGTH, &l_BCH[0]->nObj, sizeof(DWORD), &nResult, 0);
	l_BCH[0]->pObj = AllocMemory(l_BCH[0]->nObj, 0);
}
BOOL fnAesLoadKey(
	_In_ PVOID pAes
) {
	if (l_BCH[0])
		return BCryptImportKey(l_BCH[0]->ah, 0, BCRYPT_KEY_DATA_BLOB, &l_BCH[0]->kh, l_BCH[0]->pObj, l_BCH[0]->nObj, pAes, AES_BLOB_SIZE, 0);
	return 0;
}
VOID fnAesCryptEnd() {
	NTSTATUS nts = BCryptDestroyKey(l_BCH[0]->kh);
	SecureZeroMemory(l_BCH[0]->pObj, l_BCH[0]->nObj);
	FreeMemory(l_BCH[0]->pObj);
	nts = BCryptCloseAlgorithmProvider(l_BCH[0]->ah, 0);
	FreeMemory(l_BCH[0]);
}

static PVOID fnBCryptDecryptAES(
	_In_  BCRYPT_KEY_HANDLE khAES,
	_In_  PVOID             pData,
	_In_  SIZE_T            nData,
	_In_  PVOID             pIV,
	_Out_ PSIZE_T           nResult
) {
	NTSTATUS nts = BCryptDecrypt(khAES, (PUCHAR)pData, nData, 0, pIV, 16, 0, 0, nResult, 0);
	if (nts)
		return 0;
	PVOID pDecrypted = AllocMemory(*nResult, 0);
	nts = BCryptDecrypt(khAES, (PUCHAR)pData, nData, 0, pIV, 16, pDecrypted, *nResult, nResult, 0);
	if (nts) {
		FreeMemory(pDecrypted);
		return 0;
	}

	return pDecrypted;
}

PVOID fnDecryptAES(
	_In_  PVOID   pData,
	_In_  SIZE_T  nData,
	_In_  PVOID   pIV,
	_Out_ PSIZE_T nResult
) {
	if (l_BCH[0])
		return fnBCryptDecryptAES(l_BCH[0]->kh, pData, nData, pIV, nResult);
	return 0;
}

// also have to write a constructor / destructor for this too -.-
PVOID fnDecompressLZ(
	_Inout_ PVOID   pData,
	_Inout_ PSIZE_T nData
) {
	DECOMPRESSOR_HANDLE dh;
	NTSTATUS nts = CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &dh);

	// Decompress Data
	SIZE_T nDecompressed;
	nts = Decompress(dh, pData, *nData, 0, 0, &nDecompressed);
	PVOID pDecompressed = AllocMemory(nDecompressed, 0);
	nts = Decompress(dh, pData, *nData, pDecompressed, nDecompressed, &nDecompressed);

	// CleanUp
	CloseDecompressor(dh);

	*nData = nDecompressed;
	return pDecompressed;
}

PVOID fnUnpackResource(
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	if (!l_BCH[0])
		return 0;

	PVOID pResource = fnLoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	// Create KeyOBJ / Import KeySet
	BCRYPT_KEY_HANDLE kh;
	PVOID pObj = AllocMemory(l_BCH[0]->nObj, 0);
	NTSTATUS nts = BCryptImportKey(l_BCH[0]->ah, l_BCH[0]->kh, BCRYPT_AES_WRAP_KEY_BLOB, &kh, pObj, l_BCH[0]->nObj,
		((PAESEX)pResource)->KEY, sizeof(((PAESEX)pResource)->KEY), 0);

	// Copy IV to non Read-Only section / Decrypt
	BYTE pIV[16];
	CopyMemory(&pIV, ((PAESEX)pResource)->IV, 16);
	PVOID pDecrypted = fnBCryptDecryptAES(kh, (ULONG_PTR)pResource + sizeof(AESEX), nData - sizeof(AESEX), &pIV, &nData);
	nts = BCryptDestroyKey(kh);
	SecureZeroMemory(pObj, l_BCH[0]->nObj);
	FreeMemory(pObj);

	// Decompress
	SIZE_T nCompressed = *nData;
	PVOID pData = fnDecompressLZ(pDecrypted, nData);
	SecureZeroMemory(pDecrypted, nCompressed);
	FreeMemory(pDecrypted);

	// Check for Corrupted Data
	PVOID pMD5 = fnMD5HashData(pData, *nData);
	BOOL bT = fnMD5Compare(pMD5, ((PAESEX)pResource)->MD5);
	FreeMemory(pMD5);
	if (bT)
		return 0;

	return pData;
}

BOOL fnExtractResource(
	_In_ PCWSTR szFileName,
	_In_ WORD   wResID
) {
	SIZE_T nData;
	PVOID pData = fnUnpackResource(wResID, &nData);
	BOOL bT = fnWriteFileCW(szFileName, pData, nData);
	FreeMemory(pData);
	return bT;
}

// new hashing algorithnm using bcrypt md5's // to be implemented for future usecases and reimplemented in _riftCrypt
BOOL fnMd5HashingBegin() {
	l_BCH[1] = AllocMemory(sizeof(BCIB), 0);
	BCryptOpenAlgorithmProvider(&l_BCH[1]->ah, BCRYPT_MD5_ALGORITHM, 0, BCRYPT_HASH_REUSABLE_FLAG);

	SIZE_T nResult;
	NTSTATUS nts = BCryptGetProperty(l_BCH[1]->ah, BCRYPT_OBJECT_LENGTH, &l_BCH[1]->nObj, sizeof(DWORD), &nResult, 0);
	l_BCH[1]->pObj = AllocMemory(l_BCH[1]->nObj, 0);

	nts = BCryptCreateHash(l_BCH[1]->ah, &l_BCH[1]->hh, l_BCH[1]->pObj, l_BCH[1]->nObj, 0, 0, BCRYPT_HASH_REUSABLE_FLAG);
}
VOID fnMd5HashingEnd() {
	NTSTATUS nts = BCryptDestroyHash(l_BCH[1]->hh);
	FreeMemory(l_BCH[1]->pObj);
	nts = BCryptCloseAlgorithmProvider(l_BCH[1]->ah, 0);
	FreeMemory(l_BCH[1]);
}

PVOID fnMD5HashData(
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	NTSTATUS nts = BCryptHashData(l_BCH[1]->hh, pBuffer, nBuffer, 0);
	PVOID pMd5 = AllocMemory(16, 0);
	nts = BCryptFinishHash(l_BCH[1]->hh, pMd5, 16, 0);
	return pMd5;
}

BOOL fnMD5Compare(
	_In_ PVOID pMD51,
	_In_ PVOID pMD52
) {
	for (UINT8 i = 0; i < (16 / sizeof(DWORD)); i++)
		if (((PDWORD)pMD51)[i] != ((PDWORD)pMD52)[i])
			return 1;
	return 0;
}