#pragma once

#include "..\shared\depends.h"
#include "..\shared\shared.h"

HANDLE g_hCon;

PVOID ReadFileCW(_In_ PCWSTR szFileName, _In_opt_ DWORD dwFileAttribute, _Out_ PSIZE_T nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_opt_ DWORD dwFileAttribute, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
PVOID GetSectionRaw(_In_ PVOID pBuffer, _In_ PCSTR szSection, _Out_ PSIZE_T nSection);
BOOL PrintF(PCWSTR pText, WORD wAttribute, ...);