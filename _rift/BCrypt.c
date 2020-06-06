#include "pch.h"
#include "_rift_shared.h"
#ifdef _rift
#include "_rift.h"
#endif

// This file has to be reconstructed / improved as it is no longer supposed to be single use anymore.

typedef struct {
	BCRYPT_ALG_HANDLE ah;
	BCRYPT_KEY_HANDLE kh;
	PVOID pKeyObj;
	SIZE_T nKeyObj;
} BCYRPTH, *PBCRYPTH;
static PBCRYPTH l_BCH;

VOID fnLoadKey(
	_In_ PVOID pAES
) {
	l_BCH = HAlloc(sizeof(BCYRPTH), 0);
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&l_BCH->ah, BCRYPT_AES_ALGORITHM, 0, 0);

	// Create KeyOBJ / Import Key
	SIZE_T nResult;
	nts = BCryptGetProperty(l_BCH->ah, BCRYPT_OBJECT_LENGTH, &l_BCH->nKeyObj, sizeof(DWORD), &nResult, 0);
	PBYTE pAesObj = (PBYTE)HAlloc(l_BCH->nKeyObj, 0);

	nts = BCryptImportKey(l_BCH->ah, 0, BCRYPT_KEY_DATA_BLOB, &l_BCH->kh, pAesObj, l_BCH->nKeyObj, (PUCHAR)pAES, AES_BLOB_SIZE, 0);

}
VOID fnUnloadKey() {
	NTSTATUS nts = BCryptDestroyKey(l_BCH->kh);
	SecureZeroMemory(l_BCH->pKeyObj, l_BCH->nKeyObj);
	HFree(l_BCH->pKeyObj);
	nts = BCryptCloseAlgorithmProvider(l_BCH->ah, 0);
}

PVOID fnBCryptDecrypt(
	_In_  BCRYPT_KEY_HANDLE khAES,
	_In_  PVOID             pData,
	_In_  SIZE_T            nData,
	_In_  PVOID             pIV,
	_Out_ PSIZE_T           nResult
) {
	NTSTATUS nts = BCryptDecrypt(khAES, (PUCHAR)pData, nData, 0, pIV, 16, 0, 0, nResult, 0);
	if (nts)
		return 0;
	PVOID pDecrypted = HAlloc(*nResult, 0);
	nts = BCryptDecrypt(khAES, (PUCHAR)pData, nData, 0, pIV, 16, pDecrypted, *nResult, nResult, 0);
	if (nts) {
		HFree(pDecrypted);
		return 0;
	}

	return pDecrypted;
}

PVOID fnDecryptAES(
	_In_    PVOID   pData,
	_In_    SIZE_T  nData,
	_In_    PVOID   pKey,
	_Inout_ PVOID   pIV,
	_Inout_ PSIZE_T nResult
) {

	// Decrypt Data
	PVOID pDecrypted = fnBCryptDecrypt(l_BCH->kh, pData, nData, pIV, nResult);

	return pDecrypted;
}
PVOID fnDecryptWAES(
	_Inout_ PVOID   pData,
	_Inout_ PSIZE_T nData,
	_In_    PVOID   pWKey
) {
	BCRYPT_ALG_HANDLE ahAES;
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&ahAES, BCRYPT_AES_ALGORITHM, 0, 0);

	// Create KeyOBJ / Import KeySet
	SIZE_T nResult, nBL;
	BCRYPT_KEY_HANDLE khAES, khWrap;
	nts = BCryptGetProperty(ahAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nBL, sizeof(DWORD), &nResult, 0);
	PBYTE pAesObj = (PBYTE)HAlloc(nBL, 0);
	PBYTE pWrapObj = (PBYTE)HAlloc(nBL, 0);
	nts = BCryptImportKey(ahAES, 0, BCRYPT_KEY_DATA_BLOB, &khWrap, pWrapObj, nBL, (PUCHAR)pWKey, AES_BLOB_SIZE, 0);
	nts = BCryptImportKey(ahAES, khWrap, BCRYPT_AES_WRAP_KEY_BLOB, &khAES, pAesObj, nBL, ((PAESEX)pData)->KEY,
		sizeof(((PAESEX)pData)->KEY), 0);
	nts = BCryptDestroyKey(khWrap);
	HFree(pWrapObj);

	// Copy pIV to non Read-Only section
	PVOID pIV = HAlloc(sizeof(((PAESEX)pData)->IV), 0);
	CopyMemory(pIV, ((PAESEX)pData)->IV, sizeof(((PAESEX)pData)->IV));

	// Decrypt Data
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESEX), *nData - sizeof(AESEX), 0, pIV,
		sizeof(((PAESEX)pData)->IV), 0, 0, &nResult, 0);
	PBYTE pDecrypted = (PBYTE)HAlloc(nResult, 0);
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESEX), *nData - sizeof(AESEX), 0, pIV,
		sizeof(((PAESEX)pData)->IV), pDecrypted, nResult, &nResult, 0);

	// CleanUp
	HFree(pIV);
	nts = BCryptDestroyKey(khAES);
	SecureZeroMemory(pAesObj, nBL);
	HFree(pAesObj);
	nts = BCryptCloseAlgorithmProvider(ahAES, 0);

	*nData = nResult;
	return pDecrypted;
}

PVOID fnDecompressLZ(
	_Inout_ PVOID   pData,
	_Inout_ PSIZE_T nData
) {
	DECOMPRESSOR_HANDLE dh;
	NTSTATUS nts = CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &dh);

	// Decompress Data
	SIZE_T nDecompressed;
	nts = Decompress(dh, pData, *nData, 0, 0, &nDecompressed);
	PVOID pDecompressed = HAlloc(nDecompressed, 0);
	nts = Decompress(dh, pData, *nData, pDecompressed, nDecompressed, &nDecompressed);

	// CleanUp
	SecureZeroMemory(pData, nData);
	HFree(pData);
	CloseDecompressor(dh);

	*nData = nDecompressed;
	return pDecompressed;
}

static WCHAR l_szWrapKeyFile[MAX_PATH];
PVOID fnUnpackResource(
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	PWSTR szKeyBlob = (PWSTR)HAlloc(MAX_PATH, 0);
	PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->szCD, l_szWrapKeyFile);
	DWORD nKeyBlob;
	PVOID pWKey = fnAllocReadFileW(szKeyBlob, &nKeyBlob);

	PVOID pResource = fnLoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	PVOID pData = fnDecryptWAES(pResource, nData, pWKey);
	HFree(pWKey);
	pData = fnDecompressLZ(pData, nData);

	PVOID pMD5 = fnMD5HashData(pData, *nData);
	BOOL bT = fnMD5Compare(pMD5, ((PAESEX)pResource)->MD5);
	HFree(pMD5);
	if (!bT)
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
	HFree(pData);
	return bT;
}

VOID fnAllocUnpacker(
	_In_ PCWSTR szFileName
) {
	SIZE_T nFileName;
	StringCbLengthW(szFileName, MAX_PATH * sizeof(WCHAR), &nFileName);
	CopyMemory(l_szWrapKeyFile, szFileName, nFileName + (1 * sizeof(WCHAR)));
}
VOID fnDeAllocUnpacker(
	_In_ PCWSTR szFileName
) {
	SIZE_T nFileName;
	StringCbLengthW(szFileName, MAX_PATH * sizeof(WCHAR), &nFileName);
	CopyMemory(l_szWrapKeyFile, szFileName, nFileName + (1 * sizeof(WCHAR)));
}

// new hashing algorithnm using bcrypt md5's // to be implemented for future usecases and reimplemented in _riftCrypt
PVOID fnMD5HashData(
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, 0, 0);

	// Create md5OBJ
	SIZE_T nResult, nBL;
	NTSTATUS nts = BCryptGetProperty(ah, BCRYPT_OBJECT_LENGTH, (PUCHAR)&nBL, sizeof(DWORD), &nResult, 0);
	PBYTE pMD5Obj = (PBYTE)HAlloc(nBL, 0);
	BCRYPT_HASH_HANDLE hhMD5;
	nts = BCryptCreateHash(ah, &hhMD5, pMD5Obj, nBL, 0, 0, 0);

	// Hash Data
	nts = BCryptHashData(hhMD5, pBuffer, nBuffer, 0);
	PVOID pMD5 = HAlloc(16, 0);
	nts = BCryptFinishHash(hhMD5, pMD5, 16, 0);

	// CleanUp
	nts = BCryptDestroyHash(hhMD5);
	HFree(pMD5Obj);
	nts = BCryptCloseAlgorithmProvider(ah, 0);

	return pMD5;
}

BOOL fnMD5Compare(
	_In_ PVOID pMD51,
	_In_ PVOID pMD52
) {
	for (UINT8 i = 0; i < (16 / sizeof(DWORD)); i++)
		if (((PDWORD)pMD51)[i] != ((PDWORD)pMD52)[i])
			return FALSE;
	return TRUE;
}