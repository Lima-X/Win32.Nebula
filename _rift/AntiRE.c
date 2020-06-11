#include "pch.h"
#include "_rift.h"

BOOL fnAntiRE() {
	IAntiDebug();
	IAntiDllInject();
}

BOOL fnErasePeHeader() {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_PIB->hMH;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	DWORD dwProtect;
	SIZE_T wHdr = pNTHeader->OptionalHeader.SizeOfHeaders;
	VirtualProtect(g_PIB->hMH, wHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
	ZeroMemory(g_PIB->hMH, wHdr);
	VirtualProtect(g_PIB->hMH, wHdr, dwProtect, &dwProtect);
	return TRUE;
}