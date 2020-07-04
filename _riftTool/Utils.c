#include "_riftTool.h"

// File I/O
PVOID ReadFileCW(
	_In_     PCWSTR  szFileName,
	_In_opt_ DWORD   dwFileAttribute,
	_Out_    PSIZE_T nFileSize
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	PVOID pRet = 0;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, dwFileAttribute, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pFile = AllocMemory(liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bT = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, 0);
	if (!bT) {
		FreeMemory(pFile);
		goto EXIT;
	}

	pRet = pFile;
EXIT:
	CloseHandle(hFile);
	return pRet;
}
BOOL WriteFileCW(
	_In_     PCWSTR pFileName,
	_In_opt_ DWORD  dwFileAttribute,
	_In_     PVOID  pBuffer,
	_In_     SIZE_T nBuffer
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, dwFileAttribute, 0);
	if (hFile) {
		SIZE_T nWritten;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &nWritten, 0);
		CloseHandle(hFile);

		return bT;
	}
	else
		return FALSE;
}

PVOID GetSection(
	_In_  PVOID   pBuffer,
	_In_  PCSTR   szSection,
	_Out_ PSIZE_T nSection
) {
	// Get Nt Headers
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Find Section
	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (UINT8 j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != szSection[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			*nSection = pSHdr->SizeOfRawData;
			return (PTR)pBuffer + (PTR)pSHdr->PointerToRawData;
		}
	}

	return 0;
}

// shitty debug/info print function
BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)g_pBuf, 0x800, pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)g_pBuf, 0x800, (PUINT32)&nBufLen);
	SetConsoleTextAttribute(g_hCon, wAttribute);
	WriteConsoleW(g_hCon, g_pBuf, nBufLen, &nBufLen, 0);

	va_end(vaArg);
	return nBufLen;
}