#include "pch.h"
#include "_rift.h"

BOOL fnAntiRE() {
	fnAntiDebug();
	fnAntiDllInject();
}

VOID Erase_PE_Header() {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_hmMH;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (pNTHeader->FileHeader.SizeOfOptionalHeader) {
		DWORD Protect;
		WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
		VirtualProtect(g_hmMH, Size, PAGE_EXECUTE_READWRITE, &Protect);
		ZeroMemory(g_hmMH, Size);
		VirtualProtect(g_hmMH, Size, Protect, &Protect);
	}
}