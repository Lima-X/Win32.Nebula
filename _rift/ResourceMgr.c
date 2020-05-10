#include "pch.h"
#include "_rift.h"

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
}

PVOID fnLoadResourceW(
	_In_  WORD   wResID,
	_In_  PCWSTR lpResType,
	_Out_ PDWORD dwBufferSize
) {
	HRSRC hResInfo = FindResourceW(0, MAKEINTRESOURCE(wResID), lpResType);
	if (hResInfo) {
		HGLOBAL hResData = LoadResource(0, hResInfo);
		if (hResData) {
			PVOID lpBuffer = LockResource(hResData);
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
	HANDLE hFile = CreateFileW(lpFileName, GENERIC_ALL, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
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