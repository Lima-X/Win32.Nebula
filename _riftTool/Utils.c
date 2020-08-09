#include "_riftTool.h"

// File I/O
void* ReadFileCW(
	_In_     PCWSTR  szFileName,
	_In_opt_ DWORD   dwFileAttribute,
	_Out_    size_t* nFileSize
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	void* pRet = 0;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, dwFileAttribute, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	void* pFile = malloc(liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bT = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, 0);
	if (!bT) {
		free(pFile);
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
	_In_     void*  pBuffer,
	_In_     size_t nBuffer
) {
	if (!dwFileAttribute)
		dwFileAttribute = FILE_ATTRIBUTE_NORMAL;

	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, dwFileAttribute, 0);
	if (hFile) {
		size_t nWritten;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &nWritten, 0);
		CloseHandle(hFile);

		return bT;
	} else
		return FALSE;
}

void* GetSectionRaw(
	_In_  void*   pBuffer,
	_In_  PCSTR   szSection,
	_Out_ size_t* nSection
) {
	// Get Nt Headers
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Find Section
	for (uint8 i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((ptr)pOHdr + (ptr)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (uint8 j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != szSection[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			*nSection = pSHdr->SizeOfRawData;
			return (ptr)pBuffer + (ptr)pSHdr->PointerToRawData;
		}
	}

	return 0;
}

// shitty debug/info print function
BOOL PrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	void* hBuf = malloc(0x1000);
	size_t nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)hBuf, 0x800, pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)hBuf, 0x800, &nBufLen);
	if (wAttribute)
		SetConsoleTextAttribute(g_hCon, wAttribute);
	WriteConsoleW(g_hCon, hBuf, nBufLen, &nBufLen, NULL);
	free(hBuf);

	va_end(vaArg);
	return nBufLen;
}