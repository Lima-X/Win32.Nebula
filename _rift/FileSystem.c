#include "pch.h"
#include "_rift.h"

BOOL fnWriteFileW(
	_In_ PCWSTR pFileName,
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	HANDLE hFile = CreateFileW(pFileName, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, 0);
		CloseHandle(hFile);

		if (bT)
			return TRUE;
		else
			return FALSE;
	} else
		return FALSE;
}