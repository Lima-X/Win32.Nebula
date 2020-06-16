#pragma once

#include <Windows.h>
#include <strsafe.h>

#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>

#include "..\_rift\_rift_shared.h"

HANDLE g_hCon;
PVOID  g_pBuf;

PVOID ReadFileCW(_In_ PCWSTR szFileName, _In_opt_ DWORD dwFileAttribute, _Out_ PSIZE_T nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_opt_ DWORD dwFileAttribute, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);

PVOID GetSection(_In_ PVOID pBuffer, _In_ PCSTR szSection, _Out_ PSIZE_T nSection);

PBYTE Base64Encode(_In_ PBYTE pBuffer, _In_ SIZE_T nBuffer, _Out_ PSIZE_T nResult);

BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...);