#include "_rift.h"

/* CryptoService Constructor/Destructor */
BOOL ECryptBegin(
	_In_  PVOID pBlob,
	_Out_ PCIB  cib
) {
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&cib->ah, BCRYPT_AES_ALGORITHM, NULL, NULL);
	SIZE_T nResult;
	nts = BCryptGetProperty(cib->ah, BCRYPT_OBJECT_LENGTH, &cib->nObj, sizeof(DWORD), &nResult, NULL);
	cib->pObj = AllocMemory(cib->nObj);
	nts = BCryptImportKey(cib->ah, NULL, BCRYPT_KEY_DATA_BLOB, &cib->uHandle.kh, cib->pObj, cib->nObj, pBlob, AES_BLOB_SIZE, NULL);
	return nts;
}
VOID ECryptEnd(
	_In_ PCIB cib
) {
	NTSTATUS nts = BCryptDestroyKey(cib->uHandle.kh);
	SecureZeroMemory(cib->pObj, cib->nObj);
	FreeMemory(cib->pObj);
	nts = BCryptCloseAlgorithmProvider(cib->ah, NULL);
	FreeMemory(cib);
}

/* Internal Decryption Subroutine */
PVOID IAesDecrypt(
	_In_  BCRYPT_KEY_HANDLE kh,
	_In_  PVOID             pData,
	_In_  SIZE_T            nData,
	_In_  PVOID             pIv,
	_Out_ PSIZE_T           nResult
) {
	NTSTATUS nts = BCryptDecrypt(kh, pData, nData, NULL, pIv, 16, NULL, 0, nResult, NULL);
	if (nts)
		return NULL;

	PVOID pDecrypted = AllocMemory(*nResult);
	nts = BCryptDecrypt(kh, pData, nData, NULL, pIv, 16, pDecrypted, *nResult, nResult, NULL);
	if (nts) {
		FreeMemory(pDecrypted);
		return NULL;
	}

	return pDecrypted;
}

/* String Decryption */
PCWSTR EDecryptString(
	_In_  PCIB    cib,
	_In_  PCSTR   pString,
	_Out_ PSIZE_T nResult
) {
	StringCchLengthA(pString, STRSAFE_MAX_CCH, nResult);
	PVOID pData = EBase64DecodeA(pString, *nResult, nResult);

	PVOID pIv = AllocMemory(16);
	ZeroMemory(pIv, 16);
	PCWSTR sz = IAesDecrypt(cib->uHandle.kh, pData, *nResult, pIv, nResult);
	FreeMemory(pIv);
	FreeMemory(pData);

	return sz;
}

/* Resource Unpacking */
PVOID IDecompressLZ(
	_In_  PVOID   pData,
	_In_  SIZE_T  nData,
	_Out_ PSIZE_T nResult
) {
	COMPRESSOR_HANDLE ch;
	if (CreateDecompressor(COMPRESS_ALGORITHM_LZMS, NULL, &ch)) {
		Decompress(ch, pData, nData, NULL, 0, &nResult);
		PVOID pDecompressed = AllocMemory(nResult);
		if (pDecompressed) {
			if (Decompress(ch, pData, nData, pDecompressed, nResult, &nResult)) {
				CloseDecompressor(ch);
				return pDecompressed;
			}
		}
	}

	return NULL;
}
PVOID EUnpackResource(
	_In_  PCIB    cib,
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	PVOID pResource = ELoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return NULL;

	// Unwarp Key and Import it if not already imported
	BCRYPT_KEY_HANDLE kh;
	PVOID pObj = AllocMemory(cib->nObj);
	BCryptImportKey(cib->ah, cib->uHandle.kh, BCRYPT_AES_WRAP_KEY_BLOB, &kh, pObj, cib->nObj,
		((PAESIB)pResource)->Key, sizeof(((PAESIB)pResource)->Key), NULL);

	// Move Iv to modifieable location
	PVOID pIv = AllocMemory(16);
	CopyMemory(&pIv, ((PAESIB)pResource)->Iv, 16);

	// Decrypt Data
	PVOID pDecrypted = IAesDecrypt(kh, ((PAESIB)pResource)->Data, *nData - sizeof(AESIB), &pIv, nData);
	FreeMemory(pIv);
	BCryptDestroyKey(kh);
	SecureZeroMemory(pObj, cib->nObj);
	FreeMemory(pObj);

	// Decompress
	SIZE_T nCompressed = *nData;
	PVOID pData = IDecompressLZ(pDecrypted, nData, &nData);
	SecureZeroMemory(pDecrypted, nCompressed);
	FreeMemory(pDecrypted);

	// Check for Corrupted Data
	PVOID pMd5 = AllocMemory(16);
	EMd5HashData(pMd5, pData, *nData);
	BOOL bT = EMd5Compare(pMd5, ((PAESIB)pResource)->Md5);
	FreeMemory(pMd5);
	if (bT)
		return NULL;

	return pData;
}

/* Md5 Hashing */
PVOID EMd5HashData(
	_In_  PVOID  pBuffer,
	_In_  SIZE_T nBuffer
) {
	PCIB cib = AllocMemory(sizeof(CIB));
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&cib->ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	SIZE_T nResult;
	nts = BCryptGetProperty(cib->ah, BCRYPT_OBJECT_LENGTH, &cib->nObj, sizeof(DWORD), &nResult, NULL);
	cib->pObj = AllocMemory(cib->nObj);

	nts = BCryptCreateHash(cib->ah, &cib->uHandle.hh, cib->pObj, cib->nObj, NULL, 0, NULL);
	nts = BCryptHashData(cib->uHandle.hh, pBuffer, nBuffer, 0);
	PVOID pMd5 = AllocMemory(MD5_SIZE);
	nts = BCryptFinishHash(cib->uHandle.hh, pMd5, 16, NULL);

	nts = BCryptDestroyHash(cib->uHandle.hh);
	FreeMemory(cib->pObj);
	nts = BCryptCloseAlgorithmProvider(cib->ah, NULL);
	FreeMemory(cib);

	return pMd5;
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