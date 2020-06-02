#include "pch.h"
#include "_rift.h"

PVOID fnAllocReadFileW(
	_In_  PCWSTR  szFileName,
	_Out_ PSIZE_T nFileSize
) {
	PVOID pRet = 0;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bs = GetFileSizeEx(hFile, &liFS);
	if (!bs || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pFile = HeapAlloc(g_hPH, 0, liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bs = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, 0);
	if (!bs) {
		HeapFree(g_hPH, 0, pFile);
		goto EXIT;
	}

	pRet = pFile;
EXIT:
	CloseHandle(hFile);
	return pRet;
}

BOOL fnWriteFileCW(
	_In_ PCWSTR pFileName,
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, 0);
		CloseHandle(hFile);

		return bT;
	} else
		return FALSE;
}

PCWSTR fnGetFileNameFromPathW(
	_In_ PCWSTR pPath
) {
	SIZE_T nResult;
	StringCchLengthW(pPath, MAX_PATH, &nResult);

	for (UINT16 i = nResult; i > 2; i--) {
		if (pPath[i - 1] == L'\\')
			return pPath + i;
	}

	return 0;
}