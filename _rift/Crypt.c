#include "pch.h"
#include "_rift.h"

/* CryptoService Constructor/Destructor */
BOOL ECryptBegin(
	_In_  PVOID pBlob,
	_Out_ PCIB  cib
) {
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&cib->ah, BCRYPT_AES_ALGORITHM, 0, 0);
	SIZE_T nResult;
	nts = BCryptGetProperty(cib->ah, BCRYPT_OBJECT_LENGTH, &cib->nObj, sizeof(DWORD), &nResult, 0);
	cib->pObj = AllocMemory(cib->nObj);
	nts = BCryptImportKey(cib->ah, 0, BCRYPT_KEY_DATA_BLOB, &cib->uHandle.kh, cib->pObj, cib->nObj, pBlob, AES_BLOB_SIZE, 0);
	return nts;
}
VOID ECryptEnd(
	_In_ PCIB cib
) {
	NTSTATUS nts = BCryptDestroyKey(cib->uHandle.kh);
	SecureZeroMemory(cib->pObj, cib->nObj);
	FreeMemory(cib->pObj);
	nts = BCryptCloseAlgorithmProvider(cib->ah, 0);
	FreeMemory(cib);
	cib = 0;
}

/* Internal Decryption Subroutine */
PVOID IAesDecrypt(
	_In_  BCRYPT_KEY_HANDLE kh,
	_In_  PVOID             pData,
	_In_  SIZE_T            nData,
	_In_  PVOID             pIv,
	_Out_ PSIZE_T           nResult
) {
	NTSTATUS nts = BCryptDecrypt(kh, pData, nData, 0, pIv, 16, 0, 0, nResult, 0);
	if (nts)
		return 0;

	PVOID pDecrypted = AllocMemory(*nResult);
	nts = BCryptDecrypt(kh, pData, nData, 0, pIv, 16, pDecrypted, *nResult, nResult, 0);
	if (nts) {
		FreeMemory(pDecrypted);
		return 0;
	}

	return pDecrypted;
}

/* String Decryption */
PCWSTR EDecryptString(
	_In_  PCIB    cib,
	_In_  PCWSTR  pBuffer,
	_In_  SIZE_T  nBuffer,
	_Out_ PSIZE_T nResult
) {
	PVOID pData = EBase64Decode(pBuffer, nBuffer, nResult);

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
	if (CreateDecompressor(COMPRESS_ALGORITHM_LZMS, 0, &ch)) {
		Decompress(ch, pData, nData, 0, 0, &nResult);
		PVOID pDecompressed = AllocMemory(nResult);
		if (pDecompressed) {
			if (Decompress(ch, pData, nData, pDecompressed, nResult, &nResult)) {
				CloseDecompressor(ch);
				return pDecompressed;
			}
		}
	}

	return 0;
}
PVOID EUnpackResource(
	_In_  PCIB    cib,
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	PVOID pResource = ELoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	// Unwarp Key and Import it if not already imported
	BCRYPT_KEY_HANDLE kh;
	PVOID pObj = AllocMemory(cib->nObj);
	BCryptImportKey(cib->ah, cib->uHandle.kh, BCRYPT_AES_WRAP_KEY_BLOB, &kh, pObj, cib->nObj,
		((PAESIB)pResource)->KEY, sizeof(((PAESIB)pResource)->KEY), 0);

	// Move IV to modifieable location
	PVOID pIV = AllocMemory(16);
	CopyMemory(&pIV, ((PAESIB)pResource)->IV, 16);

	// Decrypt Data
	PVOID pDecrypted = IAesDecrypt(kh, (PTR)pResource + sizeof(AESIB), *nData - sizeof(AESIB), &pIV, nData);
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
	BOOL bT = EMd5Compare(pMd5, ((PAESIB)pResource)->MD5);
	FreeMemory(pMd5);
	if (bT)
		return 0;

	return pData;
}


/* MD5 Hashing */
PVOID EMd5HashData(
	_In_  PVOID  pBuffer,
	_In_  SIZE_T nBuffer
) {
	PCIB cib = AllocMemory(sizeof(CIB));
	BCryptOpenAlgorithmProvider(&cib->ah, BCRYPT_MD5_ALGORITHM, 0, 0);
	SIZE_T nResult;
	NTSTATUS nts = BCryptGetProperty(cib->ah, BCRYPT_OBJECT_LENGTH, &cib->nObj, sizeof(DWORD), &nResult, 0);
	cib->pObj = AllocMemory(cib->nObj);

	nts = BCryptCreateHash(cib->ah, &cib->uHandle.hh, cib->pObj, cib->nObj, 0, 0, 0);
	nts = BCryptHashData(cib->uHandle.hh, pBuffer, nBuffer, 0);
	PVOID pMd5 = AllocMemory(MD5_SIZE);
	nts = BCryptFinishHash(cib->uHandle.hh, pMd5, 16, 0);

	nts = BCryptDestroyHash(cib->uHandle.hh);
	FreeMemory(cib->uHandle.hh);
	nts = BCryptCloseAlgorithmProvider(cib->ah, 0);
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