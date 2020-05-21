#include "pch.h"
#include "_rift.h"

/* Unused as all the resources are encrypted anyway
BOOL fnExtractResourceW(
	_In_ WORD   wResID,
	_In_ PCWSTR lpResType,
	_In_ PCWSTR lpFileName
) {
	DWORD dwBuffersize;
	PVOID lpBuffer = fnLoadResourceW(wResID, lpResType, &dwBuffersize);
	if (lpBuffer && dwBuffersize)
		if (fnSaveResourceW(lpFileName, lpBuffer, dwBuffersize))
			return TRUE;

	return FALSE;
} */

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

BOOL fnUnpackResource(
	_In_ PCWSTR szInFN,
	_In_ PCWSTR szOutFN,
	_In_ WORD   wResID
) {
	PWSTR szKeyBlob = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
	PathCchCombine(szKeyBlob, MAX_PATH, g_szCD, szInFN);
	DWORD nKeyBlob;
	PVOID pWKey = fnLoadFileW(szKeyBlob, &nKeyBlob);


	DWORD nResLen;
	PVOID pRiftDllRes = fnLoadResourceW(wResID, L"RT_RCDATA", &nResLen);
	if (!pRiftDllRes)
		return 0;



}