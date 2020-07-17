#include "_riftldr.h"

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

VOID IConvertKeyToBlob(
	_In_  PUUID pKey,
	_Out_ PVOID pBlob
) {
	// Actually implement Bcrypt Import and Export instead of doing it like this....
	CopyMemory(pBlob, &((BCRYPT_KEY_DATA_BLOB_HEADER){ BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, AES_KEY_SIZE }),
		sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
	CopyMemory((PTR)pBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), pKey, AES_KEY_SIZE);
}
VOID IWrapKey(
	_In_  PCIB  pKey,
	_In_  PCIB  pWrap,
	_Out_ PVOID pBlob
) {

}

STATUS IValidateKey( // Checks if a Key can decrypt sampledata without opening a plaintext attack
	_In_ PCIB  cib,  // Key to be evaluated
	_In_ PVOID pData // Sampledata to Decrypt (has to be 512-Bytes in total)
) {

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
// TODO: Use Ansistrings internaly then convert to Unicode
DEPRECATED PCWSTR EDecryptString(
	_In_  PCIB    cib,
	_In_  PCSTR   pString,
	_Out_ PSIZE_T nResult
) {
	StringCchLengthA(pString, STRSAFE_MAX_CCH, nResult);
	// PVOID pData = EBase64DecodeA(pString, *nResult, nResult);

	PVOID pIv = AllocMemory(16);
	ZeroMemory(pIv, 16);
	// PCWSTR sz = IAesDecrypt(cib->uHandle.kh, pData, *nResult, pIv, nResult);
	FreeMemory(pIv);
	// FreeMemory(pData);

	// return sz;
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

	// Decrypt Data
	PVOID pIv = AllocMemory(16);
	CopyMemory(&pIv, ((PAESIB)pResource)->Iv, 16);
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
	MD5 pHash;
	EMd5HashData(pData, *nData, &pHash);
	if (!CompareMemory(&pHash, &((PAESIB)pResource)->Md5, 16))
		return pData;
	FreeMemory(pData);
	return NULL;
}

/* Md5 Hashing */
BOOL EMd5HashData(
	_In_  PVOID  pBuffer,
	_In_  SIZE_T nBuffer,
	_Out_ PMD5   pHash
) {
	PCIB cib = AllocMemory(sizeof(CIB));
	NTSTATUS nts = BCryptOpenAlgorithmProvider(&cib->ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	SIZE_T nResult;
	nts = BCryptGetProperty(cib->ah, BCRYPT_OBJECT_LENGTH, &cib->nObj, sizeof(DWORD), &nResult, NULL);
	cib->pObj = AllocMemory(cib->nObj);

	nts = BCryptCreateHash(cib->ah, &cib->uHandle.hh, cib->pObj, cib->nObj, NULL, 0, NULL);
	nts = BCryptHashData(cib->uHandle.hh, pBuffer, nBuffer, 0);
	nts = BCryptFinishHash(cib->uHandle.hh, pHash, 16, NULL);

	nts = BCryptDestroyHash(cib->uHandle.hh);
	FreeMemory(cib->pObj);
	nts = BCryptCloseAlgorithmProvider(cib->ah, NULL);
	FreeMemory(cib);
	return nts;
}
BOOL EMd5Compare(
	_In_ PMD5 pHash1,
	_In_ PMD5 pHash2
) {
	for (UINT8 i = 0; i < (16 / sizeof(DWORD)); i++)
		if (((PDWORD)pHash1)[i] != ((PDWORD)pHash2)[i])
			return 1;
	return 0;
}