#include "_riftldr.h"

/* Anti Debugger / Debugger Detection *//////////////////////////////////////////////////////////////////////////////////////////////////////////////
STATIC HMODULE hNtDll;

// Rewrite: Do it manually, by reading the flag directly from the PEB
static BOOL IBasicDebuggerCheck() {
	BOOL bT = IsDebuggerPresent();
	if (!bT) {
		BOOL bDP;
		bT = CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDP);
		if (bT)
			return bDP;
		else
			return FALSE;
	} else
		return bT;
}

// ICheckProcessDebugFlags will return true if
// the EPROCESS->NoDebugInherit is == FALSE,
// the reason we check for false is because
// the NtQueryProcessInformation function returns the
// inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
static BOOL ICheckProcessDebugFlags() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	DWORD NoDebugInherit;
	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1f, // ProcessDebugFlags
		&NoDebugInherit, 4, 0);

	if (!nts)
		return FALSE;

	if (!NoDebugInherit)
		return TRUE;
	else
		return FALSE;
}

// This function uses NtQuerySystemInformation
// to try to retrieve a handle to the current
// process's debug object handle. If the function
// is successful it'll return true which means we're
// being debugged or it'll return false if it fails
// or the process isn't being debugged
static BOOL IDebugObjectCheck() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	HANDLE hDebugObject;
	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1e, // ProcessDebugObjectHandle
		&hDebugObject, 4, 0);

	if (!nts)
		return FALSE;

	if (hDebugObject)
		return TRUE;
	else
		return FALSE;
}

// EHideThread will attempt to use
// NtSetInformationThread to hide a thread
// from the debugger, Passing NULL for
// hThread will cause the function to hide the thread
// the function is running in. Also, the function returns
// false on failure and true on success
BOOL EHideThread(
	_In_opt_ HANDLE hThread
) {
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	// Get NtSetInformationThread
	pNtSetInformationThread fnNtSIT = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

	// Shouldn't fail
	if (!fnNtSIT)
		return FALSE;

	// Set the thread info
	NTSTATUS nts;
	if (!hThread)
		nts = fnNtSIT(GetCurrentThread(),
			0x11, // HideThreadFromDebugger
			0, 0);
	else
		nts = fnNtSIT(hThread, 0x11, 0, 0);

	if (!nts)
		return FALSE;
	else
		return TRUE;
}

// ICheckOutputDebugString checks whether or
// OutputDebugString causes an error to occur
// and if the error does occur then we know
// there's no debugger, otherwise if there IS
// a debugger no error will occur
static BOOL ICheckOutputDebugString() {
	SetLastError(0);
	OutputDebugStringW(L"dbgC");
	if (!GetLastError())
		return TRUE;
	else
		return FALSE;
}

// The IInt2DCheck function will check to see if a debugger
// is attached to the current process. It does this by setting up
// SEH and using the Int 2D instruction which will only cause an
// exception if there is no debugger. Also when used in OllyDBG
// it will skip a byte in the disassembly and will create
// some havoc.
static BOOL IInt2DCheck() {
	__try {
		__asm {
			int 0x2d
			xor eax, eax
			add eax, 2
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return TRUE;
}

// The function will attempt to open csrss.exe with
// PROCESS_ALL_ACCESS rights if it fails we're
// not being debugged however, if its successful we probably are
//static BOOL ITryOpenCsrss() {
//	// If we're being debugged and the process has
//	// SeDebugPrivileges privileges then this call
//	// will be successful, note that this only works
//	// with PROCESS_ALL_ACCESS.
//
//	// Grab the export from NtDll
//	typedef HANDLE(NTAPI* pfnCsrGetProcessId)();
//	pfnCsrGetProcessId CsrGetProcessId = (pfnCsrGetProcessId)GetProcAddress(hNtDll, "CsrGetProcessId");
//	DWORD dwCsrss = CsrGetProcessId();
//	PDWORD pCsrss = &dwCsrss;
//
//	SIZE_T nProcesses = 1;
//	if (!dwCsrss)
//		pCsrss = EGetProcessIdbyName(L"csrss.exe", &nProcesses);
//
//	BOOL bT = FALSE;
//	for (UINT i = 0; i < nProcesses; i++) {
//		HANDLE hCsrss = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pCsrss[i]);
//		if (hCsrss) {
//			bT = TRUE;
//			CloseHandle(hCsrss);
//			break;
//		}
//	}
//
//	if (!dwCsrss)
//		FreeMemory(pCsrss);
//
//	return bT;
//}
//

// CheckCloseHandle will call CloseHandle on an invalid
// DWORD aligned value and if a debugger is running an exception
// will occur and the function will return true otherwise it'll
// return false
static BOOL ICheckCloseHandle() {
	__try {
		CloseHandle(0xffffffff);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;
}

LONG WINAPI IUnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers) {
	// Restore old UnhandledExceptionFilter
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);

	// Skip the exception code
	pExcepPointers->ContextRecord->Eip += 2;

	return EXCEPTION_CONTINUE_EXECUTION;
}
VOID ISehUnhandledException() {
	SetUnhandledExceptionFilter(IUnhandledExcepFilter);
	__asm {
		xor eax, eax
		div eax
	}

	// Execution resumes here if there is no debugger
	// or if there is a debugger it will never
	// reach this point of execution
}

static DWORD WINAPI thAntiDebug(_In_ PVOID pParam);
BOOL IAntiDebug() {
	hNtDll = GetModuleHandleW(L"ntdll.dll");
	EHideThread(0);
	//	ITryOpenCsrss();
	CreateThread(0, 0, thAntiDebug, 0, 0, 0);
}

static DWORD WINAPI thAntiDebug(
	_In_ PVOID pParam
) {
	UNREFERENCED_PARAMETER(pParam);
	EHideThread(0);

	while (TRUE) {
		BOOL bT = IBasicDebuggerCheck();
		if (bT)	break;
		bT = ICheckProcessDebugFlags();
		if (bT) break;
		bT = IDebugObjectCheck();
		if (bT) break;
		bT = ICheckOutputDebugString();
		if (bT) break;
		bT = IInt2DCheck();
		if (bT) break;
		bT = ICheckCloseHandle();
		if (bT) break;

		Sleep(1000);
	}

	return 0;
}

/* Anti DllInjection *///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL IAntiDllInject() {

}

static PCWSTR l_szAllowedModules[] = {
	L"kernel32.dll",
	L"ntdll.dll",
	L"user32.dll",
	L"msvcrt.dll"
};
DWORD WINAPI thCheckModules(
	_In_ PVOID pParam
) {
	UNREFERENCED_PARAMETER(pParam);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE)
		return FALSE;

	// Get a list of all the modules in this process.
	DWORD nResult;
	BOOL bs = K32EnumProcessModules(hProcess, NULL, 0, &nResult);
	HMODULE* hMods = (HMODULE*)AllocMemory(nResult);
	bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
	if (bs)
		for (UINT8 i = 0; i < nResult / sizeof(HMODULE); i++) {
			WCHAR szModuleName[MAX_PATH];

			// Get the full path to the module's file.
			if (K32GetModuleFileNameExW(hProcess, hMods[i], szModuleName, MAX_PATH)) {

			}
		}

	FreeMemory(hMods);
	CloseHandle(hProcess);

	return 0;
}

/* Hook LoadLibrary/Ex to prevent native Dll Injection.
   Can be bypassed by Manual Mapping! */
static PCWSTR l_AllowedLibraries[] = {
	L""
};
static HMODULE(WINAPI* RLoadLibraryW)(_In_ LPCWSTR lpLibFileName) = LoadLibraryW;
HMODULE WINAPI HLoadLibraryW(_In_ LPCWSTR lpLibFileName) {
	for (UINT8 i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
		if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
			return RLoadLibraryW(lpLibFileName);
	return NULL;
}
static HMODULE(WINAPI* RLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags) = LoadLibraryExW;
HMODULE WINAPI HLoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags) {
	for (UINT8 i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
		if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
			return RLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	return NULL;
}
BOOL IHookLoadLibrary() {
	if (DetourTransactionBegin())
		goto EXIT;

	// Update all Threads
	HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTSnap == INVALID_HANDLE_VALUE)
		goto EXIT;
	THREADENTRY32 te; te.dwSize = sizeof(te);
	HANDLE hThread[0x20]; // Allocate Dynamically in the future
	UINT8 nThread = 0;
	if (Thread32First(hTSnap, &te)) {
		do {
			hThread[nThread] = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			DetourUpdateThread(hThread[nThread]);
			nThread++;
		} while (Thread32Next(hTSnap, &te));
	}
	else {
		CloseHandle(hTSnap);
		goto EXIT;
	}

	// Detour LoadLibrary Functions
	DetourAttach(&LoadLibraryW, HLoadLibraryW);
	DetourAttach(&LoadLibraryExW, HLoadLibraryExW);
	DetourTransactionCommit();

	// CleanUp
	for (UINT8 i = 0; i < nThread; i++)
		CloseHandle(hThread[i]);
	CloseHandle(hTSnap);
	return TRUE;

EXIT:
	DetourTransactionAbort();
	return FALSE;
}

/* Anti Reverse Engineering *////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL fnAntiRE() {
	IAntiDllInject();
	IAntiDebug();
}

BOOL fnErasePeHeader() {
	// Get Nt Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)g_PIB->hMH;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	DWORD dwProtect;
	SIZE_T nOHdr = pOHdr->SizeOfHeaders;
	VirtualProtect(g_PIB->hMH, nOHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
	SecureZeroMemory(g_PIB->hMH, nOHdr);
	VirtualProtect(g_PIB->hMH, nOHdr, dwProtect, &dwProtect);
	return TRUE;
}

EXTERN_C CONST BYTE e_HashSig[16];
EXTERN_C CONST CHAR e_pszSections[3][8];
FORCEINLINE BOOL IHashBinaryCheck() {
	// Read Binary File
	SIZE_T nFileSize;
	PVOID pFile = AllocReadFileW(g_PIB->szMFN, &nFileSize);
	if (!pFile)
		return 0;

	// Get NT Headers
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pFile;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PTR)pDosHdr + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
	if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return FALSE;

	// Prepare Hashing
	BCRYPT_ALG_HANDLE ah;
	BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
	BCRYPT_HASH_HANDLE hh;
	BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

	for (UINT8 i = 0; i < pFHdr->NumberOfSections; i++) {
		// Get Section and Check if Type is accepted
		PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((PTR)pOHdr + (PTR)pFHdr->SizeOfOptionalHeader) + i);
		if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
			continue;

		// Check for Special Section
		BOOLEAN bFlag;
		for(UINT8 j = 0; j < (sizeof(e_pszSections) / sizeof(e_pszSections[0])); j++) {
			bFlag = TRUE;
			for (UINT8 n = 0; n < IMAGE_SIZEOF_SHORT_NAME; n++) {
				if (pSHdr->Name[n] != e_pszSections[j][n]) {
					bFlag = FALSE;
					break;
				}
			} if (bFlag) {
				bFlag = j + 1;
				break;
			}
		}

		// Set Section Pointers
		PVOID pSection = (PVOID)((PTR)pDosHdr + (PTR)pSHdr->PointerToRawData);
		SIZE_T nSection = pSHdr->SizeOfRawData;

		// Select what to to
		if (bFlag == 1) {
			PVOID pHash = 0;

			// Find Hash Signature
			for (UINT j = 0; j < nSection - MD5_SIZE; j++) {
				bFlag = TRUE;
				for (UINT8 n = 0; n < MD5_SIZE; n++) {
					if (((PBYTE)pSection)[j + n] != e_HashSig[n]) {
						bFlag = FALSE;
						break;
					}
				} if (bFlag) {
					pHash = (PVOID)((PTR)pSection + j);
					break;
				}
			}

			// Hash only Data surrounding the Hash
			SIZE_T nRDataP1 = (PTR)pHash - (PTR)pSection;
			BCryptHashData(hh, pSection, nRDataP1, NULL);
			SIZE_T nRDataP2 = ((PTR)pSection + nSection) - ((PTR)pHash + MD5_SIZE);
			BCryptHashData(hh, (PUCHAR)((PTR)pHash + MD5_SIZE), nRDataP2, NULL);
		} else if (bFlag >= 2)
			continue;
		else
			BCryptHashData(hh, pSection, nSection, NULL);
	}

	PVOID pMd5 = AllocMemory(MD5_SIZE);
	BCryptFinishHash(hh, pMd5, MD5_SIZE, NULL);
	BCryptDestroyHash(hh);
	BCryptCloseAlgorithmProvider(ah, NULL);
	BOOL bT = EMd5Compare(pMd5, e_HashSig);
	FreeMemory(pMd5);
	return bT;
}

/* Thread Local Storage (TLS) Callback */
STATIC BOOLEAN l_bTlsFlag = TRUE;
EXTERN_C CONST BYTE e_SKey[28];
VOID NTAPI ITlsCb(
	_In_ PVOID DllHandle,
	_In_ DWORD dwReason,
	_In_ PVOID Reserved
) {
	UNREFERENCED_PARAMETER(DllHandle);
	UNREFERENCED_PARAMETER(dwReason);
	UNREFERENCED_PARAMETER(Reserved);
	if (l_bTlsFlag) {
		{	// Partially initialize PIB (Neccessary Fields only)
			HANDLE hPH = GetProcessHeap();
			g_PIB = (PPIB)HeapAlloc(hPH, NULL, sizeof(PIB));
			g_PIB->hPH = hPH;
			HMODULE hP = GetModuleHandleW(NULL);
			GetModuleFileNameW(hP, g_PIB->szMFN, MAX_PATH);
			ECryptBegin(e_SKey, &g_PIB->sCIB.SK);
		}

		l_bTlsFlag = FALSE;
		BOOL bT = IHashBinaryCheck();
		if (bT)
			MessageBoxW(0, L"TLS InCorrect", 0, 0);
		else
			MessageBoxW(0, L"TLS Correct", 0, 0);
	}
}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_TlsCallback")
#pragma data_seg(".CRT$XLY")
PIMAGE_TLS_CALLBACK TlsCallback = ITlsCb;
#pragma data_seg()