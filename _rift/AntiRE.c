#include "pch.h"
#include "_rift.h"

BOOL fnAntiRE() {
	IAntiDllInject();
	IAntiDebug();
}

BOOL fnErasePeHeader() {
	// Get Nt Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)g_PIB->hMH;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	DWORD dwProtect;
	SIZE_T nOHdr = pOHdr->SizeOfHeaders;
	VirtualProtect(g_PIB->hMH, nOHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
	SecureZeroMemory(g_PIB->hMH, nOHdr);
	VirtualProtect(g_PIB->hMH, nOHdr, dwProtect, &dwProtect);
	return TRUE;
}

/* l_CSh (CodeSectionHash) contains the expected Hash of the CodeSection in memory */
CONST STATIC BYTE l_CSH[] = { // == 128-Bit/16-Byte
	'.', 't', 'e', 'x', 't', 'M', 'd', '5', 'S', 'i', 'g',
	0, 0, 0, 0, 0
};
FORCEINLINE BOOL IHashCodeSection() {
	// Read Binary File
	WCHAR szMFN[MAX_PATH];
	GetModuleFileNameW(0, szMFN, MAX_PATH);
	HANDLE hFile = CreateFileW(szMFN, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		return 0;

	HANDLE hPH = GetProcessHeap();
	PVOID pFile = HeapAlloc(hPH, 0, liFS.LowPart);
	if (!pFile)
		return 0;

	SIZE_T nFileSize = 0;
	bT = ReadFile(hFile, pFile, liFS.LowPart, &nFileSize, 0);
	CloseHandle(hFile);
	if (!bT || (nFileSize != liFS.LowPart)) {
		HeapFree(hPH, 0, pFile);
		return 0;
	}

	// Get Nt Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFile;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	PVOID pBoc = 0;
	SIZE_T nBoc = 0;
	CONST BYTE bSectionName[8] = { '.', 't', 'e', 'x', 't', 0, 0, 0 };
	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (UINT8 j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != bSectionName[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			pBoc = (PTR)pDosHdr + (PTR)pSHdr->PointerToRawData;
			nBoc = pSHdr->SizeOfRawData;
			break;
		}
	}

	// Hash Code/Text Section
	EMd5HashBegin();
	BYTE Md5[16];
	EMd5HashData(Md5, pBoc, nBoc);
	bT = EMd5Compare(Md5, l_CSH);
	EMd5HashEnd();

	return bT;
}

/* Thread Local Storage (TLS) Callback*/
STATIC BOOLEAN bTlsFlag = FALSE;
VOID NTAPI CbTls(PVOID DllHandle, DWORD dwReason, PVOID Reserved) {
	if (!bTlsFlag) {
		bTlsFlag = TRUE;
		BOOL bT = IHashCodeSection();
		if (bT)
			MessageBoxW(0, L"TLS", 0, 0);
	}
}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_TlsCallback")
#pragma data_seg(".CRT$XLY")
PIMAGE_TLS_CALLBACK TlsCallback = CbTls;
#pragma data_seg()