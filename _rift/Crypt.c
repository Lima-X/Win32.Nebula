#include "pch.h"
#include "_rift.h"

EXTERN_C CONST CHAR e_szB64StringKey[40];
EXTERN_C CONST BYTE e_HashSig[16];
EXTERN_C CONST CHAR e_pszSections[3][8];
















/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OLD SHIT
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

PCIB l_ciba2[2]; // [0]: WrapKey Object
                 // [1]: Md5Hash Object

/* These functions act as Constructors / Destructors, they manage internal data *////////////////////////////////////////////////////////////////////
BOOL EAesCryptBegin() {
	l_ciba2[0] = AllocMemory(sizeof(CIB));
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&l_ciba2[0]->ah, BCRYPT_AES_ALGORITHM, 0, 0);

	// Create KeyOBJ / Import Key
	SIZE_T nResult;
	nts = BCryptGetProperty(l_ciba2[0]->ah, BCRYPT_OBJECT_LENGTH, &l_ciba2[0]->nObj, sizeof(DWORD), &nResult, 0);
	l_ciba2[0]->pObj = AllocMemory(l_ciba2[0]->nObj);
}
BOOL IAesLoadWKey(
	_In_ PVOID pWAes
) {
	if (l_ciba2[0])
		return BCryptImportKey(l_ciba2[0]->ah, 0, BCRYPT_KEY_DATA_BLOB, &l_ciba2[0]->kh, l_ciba2[0]->pObj, l_ciba2[0]->nObj, pWAes, AES_BLOB_SIZE, 0);
	return 0;
}
VOID EAesCryptEnd() {
	if (l_ciba2[0]) {
		NTSTATUS nts = BCryptDestroyKey(l_ciba2[0]->kh);
		SecureZeroMemory(l_ciba2[0]->pObj, l_ciba2[0]->nObj);
		FreeMemory(l_ciba2[0]->pObj);
		nts = BCryptCloseAlgorithmProvider(l_ciba2[0]->ah, 0);
		FreeMemory(l_ciba2[0]);
		l_ciba2[0] = 0;
	}
}

PVOID IAesDecrypt(
	_In_  BCRYPT_KEY_HANDLE khAES,
	_In_  PVOID             pData,
	_In_  SIZE_T            nData,
	_In_  PVOID             pIV,
	_Out_ PSIZE_T           nResult
) {
	NTSTATUS nts = BCryptDecrypt(khAES, pData, nData, 0, pIV, 16, 0, 0, nResult, 0);
	if (nts)
		return 0;
	PVOID pDecrypted = AllocMemory(*nResult);
	nts = BCryptDecrypt(khAES, pData, nData, 0, pIV, 16, pDecrypted, *nResult, nResult, 0);
	if (nts) {
		FreeMemory(pDecrypted);
		return 0;
	}

	return pDecrypted;
}

NTSTATUS EAesUnwrapKey(
	_In_ PCIB   cib,  // Be sure to Free cib after finishing using it
	_In_ PVOID  pKey,
	_In_ SIZE_T nKey
) {
	cib->pObj = AllocMemory(l_ciba2[0]->nObj);
	return BCryptImportKey(l_ciba2[0]->ah, l_ciba2[0]->kh, BCRYPT_AES_WRAP_KEY_BLOB, &cib->kh, cib->pObj, l_ciba2[0]->nObj, pKey, nKey, 0);
}
VOID EAesFreeKey(
	_In_ PCIB cib
) {
	NTSTATUS nts = BCryptDestroyKey(cib->kh);
	SecureZeroMemory(cib->pObj, l_ciba2[0]->nObj);
	FreeMemory(cib->pObj);
}

/* Decompressor *///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static DECOMPRESSOR_HANDLE l_ch;
BOOL EDecompressBegin() {
	return !CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &l_ch);
}
VOID EDecompressEnd() {
	CloseDecompressor(l_ch);
}

PVOID IDecompressLZ(
	_Inout_ PVOID   pData,
	_Inout_ PSIZE_T nData
) {
	// Decompress Data
	SIZE_T nDecompressed;
	NTSTATUS nts = Decompress(l_ch, pData, *nData, 0, 0, &nDecompressed);
	PVOID pDecompressed = AllocMemory(nDecompressed);
	nts = Decompress(l_ch, pData, *nData, pDecompressed, nDecompressed, &nDecompressed);

	*nData = nDecompressed;
	return pDecompressed;
}

PVOID EUnpackResource(
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	if (!l_ciba2[0])
		return 0;

	PVOID pResource = ELoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	// Unwrap Key / Copy IV to non Read-Only section / Decrypt
	CIB cib;
	EAesUnwrapKey(&cib, ((PAESEX)pResource)->KEY, sizeof(((PAESEX)pResource)->KEY));
	BYTE pIV[16];
	CopyMemory(&pIV, ((PAESEX)pResource)->IV, 16);
	PVOID pDecrypted = IAesDecrypt(cib.kh, (PTR)pResource + sizeof(AESEX), *nData - sizeof(AESEX), &pIV, nData);
	EAesFreeKey(&cib);

	// Decompress
	SIZE_T nCompressed = *nData;
	PVOID pData = IDecompressLZ(pDecrypted, nData);
	SecureZeroMemory(pDecrypted, nCompressed);
	FreeMemory(pDecrypted);

	// Check for Corrupted Data
	PVOID pMd5 = AllocMemory(16);
	EMd5HashData(pMd5, pData, *nData);
	BOOL bT = EMd5Compare(pMd5, ((PAESEX)pResource)->MD5);
	FreeMemory(pMd5);
	if (bT)
		return 0;

	return pData;
}

BOOL fnExtractResource(
	_In_ PCWSTR szFileName,
	_In_ WORD   wResID
) {
	SIZE_T nData;
	PVOID pData = EUnpackResource(wResID, &nData);
	BOOL bT = WriteFileCW(szFileName, pData, nData);
	FreeMemory(pData);
	return bT;
}

BOOL EUnpackResourceBegin() {
	BOOL bT = EAesCryptBegin();
	bT |= EDecompressBegin();
	return bT |= EMd5HashBegin();
}
VOID EUnpackResourceEnd() {
	EAesCryptEnd();
	EDecompressEnd();
	EMd5HashEnd();
}

// new hashing algorithnm using bcrypt md5's // to be implemented for future usecases and reimplemented in _riftCrypt
// note: these functions can't use the Memory Macros but rather have to use the Heap Functions directly,
// because they are called from the TLS Callback Function, where the PIB is not initialized yet.
BOOL EMd5HashBegin() {
	HANDLE hPH = GetProcessHeap();
	l_ciba2[1] = HeapAlloc(hPH, 0, sizeof(CIB));
	BCryptOpenAlgorithmProvider(&l_ciba2[1]->ah, BCRYPT_MD5_ALGORITHM, 0, BCRYPT_HASH_REUSABLE_FLAG);

	SIZE_T nResult;
	NTSTATUS nts = BCryptGetProperty(l_ciba2[1]->ah, BCRYPT_OBJECT_LENGTH, &l_ciba2[1]->nObj, sizeof(DWORD), &nResult, 0);
	l_ciba2[1]->pObj = HeapAlloc(hPH, 0, l_ciba2[1]->nObj);

	nts = BCryptCreateHash(l_ciba2[1]->ah, &l_ciba2[1]->hh, l_ciba2[1]->pObj, l_ciba2[1]->nObj, 0, 0, BCRYPT_HASH_REUSABLE_FLAG);
}
VOID EMd5HashEnd() {
	HANDLE hPH = GetProcessHeap();
	NTSTATUS nts = BCryptDestroyHash(l_ciba2[1]->hh);
	HeapFree(hPH, 0, l_ciba2[1]->pObj);
	nts = BCryptCloseAlgorithmProvider(l_ciba2[1]->ah, 0);
	HeapFree(hPH, 0, l_ciba2[1]);
}

VOID EMd5HashData(
	_Out_ PVOID  pMd5,
	_In_  PVOID  pBuffer,
	_In_  SIZE_T nBuffer
) {
	NTSTATUS nts = BCryptHashData(l_ciba2[1]->hh, pBuffer, nBuffer, 0);
	nts = BCryptFinishHash(l_ciba2[1]->hh, pMd5, 16, 0);
}
BOOL EMd5Compare(
	_In_ PVOID pMD51,
	_In_ PVOID pMD52
) {
	for (UINT8 i = 0; i < (16 / sizeof(DWORD)); i++)
		if (((PDWORD)pMD51)[i] != ((PDWORD)pMD52)[i])
			return 1;
	return 0;
}