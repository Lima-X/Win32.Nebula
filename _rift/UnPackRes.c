#include "pch.h"
#include "_rift.h"

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

// Unused
BOOL fnSaveResourceW(
	_In_ PCWSTR lpFileName,
	_In_ PVOID  lpBuffer,
	_In_ DWORD  dwBufferSize
) {
	HANDLE hFile = CreateFileW(lpFileName, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, lpBuffer, dwBufferSize, &dwT, 0);
		CloseHandle(hFile);

		if (bT)
			return TRUE;
		else
			return FALSE;
	} else
		return FALSE;
}

PVOID fnLoadFileW(
	_In_  PCWSTR szFileName,
	_Out_ PDWORD nFileSize
) {
	HANDLE hWrapBlob = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hWrapBlob == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL status = GetFileSizeEx(hWrapBlob, &liFS);
	if (!status || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pWrapBlob = HeapAlloc(g_hPH, 0, liFS.LowPart);
	if (!pWrapBlob)
		goto EXIT;

	DWORD dwRead;
	status = ReadFile(hWrapBlob, pWrapBlob, liFS.LowPart, &dwRead, 0);
	if (!status) {
		HeapFree(g_hPH, 0, pWrapBlob);
		goto EXIT;
	}

	CloseHandle(hWrapBlob);
	return pWrapBlob;

EXIT:
	CloseHandle(hWrapBlob);
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
	nts = BCryptImportKey(ahAES, khWrap, BCRYPT_AES_WRAP_KEY_BLOB, &khAES, pAesObj, nBL, ((PAESBLOB)pData)->KEY,
		sizeof(((PAESBLOB)pData)->KEY), 0);
	nts = BCryptDestroyKey(khWrap);
	HeapFree(g_hPH, 0, pWrapObj);

	// Copy IV to non Read-Only section
	PVOID pIV = HeapAlloc(g_hPH, 0, sizeof(((PAESBLOB)pData)->IV));
	CopyMemory(pIV, ((PAESBLOB)pData)->IV, sizeof(((PAESBLOB)pData)->IV));

	// Decrypt Data
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESBLOB), *nData - sizeof(AESBLOB), 0, pIV,
		sizeof(((PAESBLOB)pData)->IV), 0, 0, &nResult, 0);
	PBYTE pDecrypted = (PBYTE)HeapAlloc(g_hPH, 0, nResult);
	nts = BCryptDecrypt(khAES, (ULONG_PTR)pData + sizeof(AESBLOB), *nData - sizeof(AESBLOB), 0, pIV,
		sizeof(((PAESBLOB)pData)->IV), pDecrypted, nResult, &nResult, 0);

	// CleanUp
	HeapFree(g_hPH, 0, pIV);
	nts = BCryptDestroyKey(khAES);
	HeapFree(g_hPH, 0, pAesObj);
	nts = BCryptCloseAlgorithmProvider(ahAES, 0);

	*nData = nResult;
	return pDecrypted;
}

BOOL fnDecompressLZ(
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
	HeapFree(g_hPH, 0, pData);
	CloseDecompressor(dh);

	*nData = nDecompressed;
	return pDecompressed;
}

PVOID fnUnpackResource(
	_In_  PCWSTR  szInFN,
	_In_  WORD    wResID,
	_Out_ PSIZE_T nData
) {
	PWSTR szKeyBlob = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
	PathCchCombine(szKeyBlob, MAX_PATH, g_szCD, szInFN);
	DWORD nKeyBlob;
	PVOID pWKey = fnLoadFileW(szKeyBlob, &nKeyBlob);

	PVOID pResource = fnLoadResourceW(wResID, L"RT_RCDATA", nData);
	if (!pResource)
		return 0;

	PVOID pData = fnDecryptWAES(pResource, nData, pWKey);
	pData = fnDecompressLZ(pData, nData);

	fnAllocTable();
	DWORD dwCrc = fnCRC32(pData, *nData);
	if (dwCrc != ((PAESBLOB)pResource)->CRC)
		return 0;

	return pData;
}