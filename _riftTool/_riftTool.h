#pragma once

#include "..\shared\depends.h"

extern HANDLE g_hCon;

void* ReadFileCW(_In_ PCWSTR szFileName, _In_opt_ dword dwFileAttribute, _Out_ size_t* nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_opt_ DWORD dwFileAttribute, _In_ void* pBuffer, _In_ size_t nBuffer);
PVOID GetSectionRaw(_In_ PVOID pBuffer, _In_ PCSTR szSection, _Out_ size_t* nSection);
BOOL PrintF(PCWSTR pText, WORD wAttribute, ...);


extern const md5 e_HashSig;
extern const CHAR e_pszSections[ANYSIZE_ARRAY][8];
extern const size_t e_nSections;
