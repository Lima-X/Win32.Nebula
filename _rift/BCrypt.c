#include "pch.h"
#include "_rift_shared.h"
#ifdef _rift
#include "_rift.h"
#endif

PVOID fnLoadResourceW(
	_In_  WORD   wResID,
	_In_  PCWSTR lpResType,
	_Out_ PDWORD dwBufferSize
) {
	HRSRC hResInfo = FindResourceW(0, MAKEINTRESOURCEW(wResID), lpResType);
	if (hResInfo) {
		HGLOBAL hgData = LoadResource(0, hResInfo);
		if (hgData) {
			PVOID lpBuffer = LockResource(hgData);
			if (!lpBuffer)
				return 0;

			*dwBufferSize = SizeofResource(0, hResInfo);
			if (!*dwBufferSize)
				return 0;

			return lpBuffer;
		}
	}

	return 0;
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
	PBYTE pAesObj = (PBYTE)HeapAlloc(g_hPH, 0, nBL);
	PBYTE pWrapObj = (PBYTE)HeapAlloc(g_hPH, 0, nBL);

	nts = BCryptImportKey(ahAES, 0, BCRYPT_KEY_DATA_BLOB, &khWrap, pWrapObj, nBL, (PUCHAR)pWKey, WRAP_BLOB_SIZE, 0);
	nts = BCryptImportKey(ahAES, khWrap, BCRYPT_AES_WRAP_KEY_BLOB, &khAES, pAesObj, nBL, ((PAESEX)pData)->KEY,
		sizeof(((PAESEX)pData)->KEY), 0);
	nts = BCryptDestroyKey(khWrap);
	HeapFree(g_hPH, 0, pWrapObj);

	// Copy IV to non Read-Only section
	PVOID pIV = HeapAlloc(g_hPH, 0, sizeof(((PAESEX)pData)->IV));
	CopyMemory(pIV, ((PAESEX)pData)->IV, sizeof(((PAESEX)pData)->IV));

	// Decrypt Data
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESEX), *nData - sizeof(AESEX), 0, pIV,
		sizeof(((PAESEX)pData)->IV), 0, 0, &nResult, 0);
	PBYTE pDecrypted = (PBYTE)HeapAlloc(g_hPH, 0, nResult);
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESEX), *nData - sizeof(AESEX), 0, pIV,
		sizeof(((PAESEX)pData)->IV), pDecrypted, nResult, &nResult, 0);

	// CleanUp
	HeapFree(g_hPH, 0, pIV);
	nts = BCryptDestroyKey(khAES);
	SecureZeroMemory(pAesObj, nBL);
	HeapFree(g_hPH, 0, pAesObj);
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
	PVOID pDecompressed = HeapAlloc(g_hPH, 0, nDecompressed);
	nts = Decompress(dh, pData, *nData, pDecompressed, nDecompressed, &nDecompressed);

	// CleanUp
	SecureZeroMemory(pData, nData);
	HeapFree(g_hPH, 0, pData);
	CloseDecompressor(dh);

	*nData = nDecompressed;
	return pDecompressed;
}

static WCHAR l_szWrapKeyFile[MAX_PATH];
PVOID fnUnpackResource(
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	PWSTR szKeyBlob = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
	PathCchCombine(szKeyBlob, MAX_PATH, g_szCD, l_szWrapKeyFile);
	DWORD nKeyBlob;
	PVOID pWKey = fnAllocReadFileW(szKeyBlob, &nKeyBlob);

	PVOID pResource = fnLoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	PVOID pData = fnDecryptWAES(pResource, nData, pWKey);
	HeapFree(g_hPH, 0, pWKey);
	pData = fnDecompressLZ(pData, nData);

	fnAllocTable();
	DWORD dwCrc = fnCRC32(pData, *nData);
	fnFreeTable();
	if (dwCrc != ((PAESEX)pResource)->CRC)
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
	HeapFree(g_hPH, 0, pData);
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
	PBYTE pMD5Obj = (PBYTE)HeapAlloc(g_hPH, 0, nBL);
	BCRYPT_HASH_HANDLE hhMD5;
	nts = BCryptCreateHash(ah, &hhMD5, pMD5Obj, nBL, 0, 0, 0);

	SIZE_T nHL; // 16 (128-Bit)
	nts = BCryptGetProperty(ah, BCRYPT_HASH_LENGTH, (PUCHAR)&nHL, sizeof(DWORD), &nResult, 0);

	// Hash Data
	nts = BCryptHashData(hhMD5, pBuffer, nBuffer, 0);
	PVOID pMD5 = HeapAlloc(g_hPH, 0, MD5_HASH_SIZE);
	nts = BCryptFinishHash(hhMD5, pMD5, MD5_HASH_SIZE, 0);

	// CleanUp
	nts = BCryptDestroyHash(hhMD5);
	HeapFree(g_hPH, 0, pMD5Obj);
	nts = BCryptCloseAlgorithmProvider(ah, 0);

	return pMD5;
}

BOOL fnCompareMD5(
	_In_ PVOID pMD51,
	_In_ PVOID pMD52
) {
	for (UINT8 i = 0; i < (MD5_HASH_SIZE / sizeof(DWORD)); i++)
		if (((PDWORD)pMD51)[i] != ((PDWORD)pMD52)[i])
			return FALSE;

	return TRUE;
}