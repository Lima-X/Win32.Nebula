#pragma once

#include "..\_riftldr\depends.h"
#include "..\_riftldr\shared.h"

HANDLE g_hCon;
PVOID  g_pBuf;

PVOID ReadFileCW(_In_ PCWSTR szFileName, _In_opt_ DWORD dwFileAttribute, _Out_ PSIZE_T nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_opt_ DWORD dwFileAttribute, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
PVOID GetSection(_In_ PVOID pBuffer, _In_ PCSTR szSection, _Out_ PSIZE_T nSection);
BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...);