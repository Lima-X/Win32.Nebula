#include "pch.h"
#include "_rift.h"

BOOL IIsUserAdmin() {
	PSID pSId;
	BOOL bSId = AllocateAndInitializeSid(&(SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSId);
	if (bSId) {
		if (!CheckTokenMembership(0, pSId, &bSId))
			bSId = FALSE;

		FreeSid(pSId);
	}

	return bSId;
}

PVOID ELoadResourceW(
	_In_  WORD    wResID,
	_In_  PCWSTR  pResType,
	_Out_ PSIZE_T nBufferSize
) {
	HRSRC hResInfo = FindResourceW(0, MAKEINTRESOURCEW(wResID), pResType);
	if (hResInfo) {
		HGLOBAL hgData = LoadResource(0, hResInfo);
		if (hgData) {
			PVOID lpBuffer = LockResource(hgData);
			if (!lpBuffer)
				return 0;

			*nBufferSize = SizeofResource(0, hResInfo);
			if (!*nBufferSize)
				return 0;

			return lpBuffer;
		}
	}

	return 0;
}

PDWORD EGetProcessIdbyName(
	_In_  PCWSTR  pProcessName,
	_Out_ PSIZE_T nProcesses
) {
	HANDLE hPSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hPSnap == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	PDWORD pProcesses = 0;
	if (Process32FirstW(hPSnap, &pe32)) {
		*nProcesses = 0;
		do {
			if (!lstrcmpiW(pe32.szExeFile, pProcessName)) {
				if (pProcesses)
					pProcesses = ReAllocMemory(pProcesses, sizeof(DWORD) * *nProcesses, 0);
				else
					pProcesses = AllocMemory(sizeof(DWORD), 0);

				pProcesses[*nProcesses] = pe32.th32ProcessID;
			}
		} while (Process32Next(hPSnap, &pe32));
	}

	CloseHandle(hPSnap);
	return pProcesses;
}