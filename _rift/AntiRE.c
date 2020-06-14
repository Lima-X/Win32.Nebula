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
#pragma data_seg(".data")
__declspec(allocate(".data")) DWORD l_CSH[16] = {
	0x6c60b78f, 0x9a88ef46, 0x6dc819fa, 0xa0520fd5
};
#pragma data_seg()

__declspec(noinline) BOOL IHashCodeSection() {
	// Get Nt Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)GetModuleHandleW(0);
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	PTR pBoc = 0;
	SIZE_T nBoc = 0;
	CONST BYTE bSectionName[8] = { '.', 't', 'e', 'x', 't', 0x00, 0x00, 0x00 };
	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		BOOLEAN bFlag = TRUE;
		for (UINT8 j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
			if (pSHdr->Name[j] != bSectionName[j]) {
				bFlag = FALSE;
				break;
			}
		} if (bFlag) {
			pBoc = (PTR)pDosHdr + (PTR)pSHdr->VirtualAddress;
			nBoc = pSHdr->Misc.VirtualSize;
			break;
		}
	}

	// Hash Code/Text Section
	EMd5HashBegin();
	BYTE Md5[16];
	EMd5HashData(Md5, pBoc, nBoc);
	BOOL bT = EMd5Compare(Md5, l_CSH);
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