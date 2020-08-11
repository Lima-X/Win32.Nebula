/* Most of the Code in this file gets executed before the CRT is (fully) initialized (TLS Callback),
   therefore the usage of CRT features might be unsafe */
#include "_riftldr.h"

extern const md5 e_HashSig;
extern const CHAR e_pszSections[ANYSIZE_ARRAY][8];
extern const size_t e_nSections;

namespace are {
	namespace dbg {
		/* Anti Debugger / Debugger Detection *//////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static HMODULE hNtDll;

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
			}
			else
				return bT;
		}

		// ICheckProcessDebugFlags will return true if
		// the EPROCESS->NoDebugInherit is == FALSE,
		// the reason we check for false is because
		// the NtQueryProcessInformation function returns the
		// inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
		static BOOL ICheckProcessDebugFlags() {
			// Much easier in ASM but C/C++ looks so much better
			typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, uint, void*, ULONG, PULONG);

			// Instance NtQueryInformationProcess
			pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

			dword NoDebugInherit;
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
			typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, uint, void*, ULONG, PULONG);

			// Instance NtQueryInformationProcess
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
			typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, uint, void*, ULONG);

			// Instance NtSetInformationThread
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
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
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
		//	dword dwCsrss = CsrGetProcessId();
		//	PDWORD pCsrss = &dwCsrss;
		//
		//	size_t nProcesses = 1;
		//	if (!dwCsrss)
		//		pCsrss = EGetProcessIdbyName(L"csrss.exe", &nProcesses);
		//
		//	BOOL bT = FALSE;
		//	for (uint i = 0; i < nProcesses; i++) {
		//		HANDLE hCsrss = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pCsrss[i]);
		//		if (hCsrss) {
		//			bT = TRUE;
		//			CloseHandle(hCsrss);
		//			break;
		//		}
		//	}
		//
		//	if (!dwCsrss)
		//		free(pCsrss);
		//
		//	return bT;
		//}
		//

		// CheckCloseHandle will call CloseHandle on an invalid
		// dword aligned value and if a debugger is running an exception
		// will occur and the function will return true otherwise it'll
		// return false
		static BOOL ICheckCloseHandle() {
			__try {
				CloseHandle((HANDLE)0xffffffff);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
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

		static dword WINAPI thAntiDebug(_In_ void* pParam);
		BOOL IAntiDebug() {
			hNtDll = GetModuleHandleW(L"ntdll.dll");
			EHideThread(0);
			//	ITryOpenCsrss();
			CreateThread(0, 0, thAntiDebug, 0, 0, 0);
			return 0;
		}

		static dword WINAPI thAntiDebug(
			_In_ void* pParam
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
	}

	namespace dli {
		/* Anti DllInjection *///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		BOOL IAntiDllInject() {
			return 0;

		}

		static PCWSTR l_szAllowedModules[] = {
			L"kernel32.dll",
			L"ntdll.dll",
			L"user32.dll",
			L"msvcrt.dll"
		};
		dword WINAPI thCheckModules(
			_In_ void* pParam
		) {
			UNREFERENCED_PARAMETER(pParam);
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
			if (hProcess == INVALID_HANDLE_VALUE)
				return FALSE;

			// Instance a list of all the modules in this process.
			dword nResult;
			BOOL bs = K32EnumProcessModules(hProcess, NULL, 0, &nResult);
			HMODULE* hMods = (HMODULE*)malloc(nResult);
			bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
			if (bs)
				for (uchar i = 0; i < nResult / sizeof(HMODULE); i++) {
					WCHAR szModuleName[MAX_PATH];

					// Instance the full path to the module's file.
					if (K32GetModuleFileNameExW(hProcess, hMods[i], szModuleName, MAX_PATH)) {

					}
				}

			free(hMods);
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
			for (uchar i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
				if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
					return RLoadLibraryW(lpLibFileName);
			return NULL;
		}
		static HMODULE(WINAPI* RLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ dword dwFlags) = LoadLibraryExW;
		HMODULE WINAPI HLoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ dword dwFlags) {
			for (uchar i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
				if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
					return RLoadLibraryExW(lpLibFileName, hFile, dwFlags);
			return NULL;
		}
		BOOL IHookLoadLibrary() {
			// Update all Threads
			HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (hTSnap == INVALID_HANDLE_VALUE)
				return -1;
			THREADENTRY32 te; te.dwSize = sizeof(te);
			HANDLE hThread[0x20]; // Allocate Dynamically in the future
			uchar nThread = 0;
			if (Thread32First(hTSnap, &te)) {
				if (DetourTransactionBegin())
					return -2;
				do {
					hThread[nThread] = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					DetourUpdateThread(hThread[nThread]);
					nThread++;
				} while (Thread32Next(hTSnap, &te));
			}
			else {
				CloseHandle(hTSnap);
				return -3;
			}

			// Detour LoadLibrary Functions
			DetourAttach((void**)&LoadLibraryW, HLoadLibraryW);
			DetourAttach((void**)&LoadLibraryExW, HLoadLibraryExW);
			DetourTransactionCommit();

			// CleanUp
			for (uchar i = 0; i < nThread; i++)
				CloseHandle(hThread[i]);
			CloseHandle(hTSnap);
			return TRUE;
		}
	}


	/* Anti Reverse Engineering *////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	namespace img {
		DEPRECATED BOOL fnErasePeHeader() {
			// Instance Nt Headers
			PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)g_PIB->sMod.hM;
			PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pDosHdr + pDosHdr->e_lfanew);
			if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
			PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
			if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return FALSE;

			dword dwProtect;
			size_t nOHdr = pOHdr->SizeOfHeaders;
			VirtualProtect(g_PIB->sMod.hM, nOHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
			SecureZeroMemory(g_PIB->sMod.hM, nOHdr);
			VirtualProtect(g_PIB->sMod.hM, nOHdr, dwProtect, &dwProtect);
			return TRUE;
		}

		// Will Redo in Memory
		FORCEINLINE BOOL IHashBinaryCheck() {
			// Read Binary File
			size_t nFileSize;
			void* pFile = utl::AllocReadFileW(g_PIB->sMod.szMFN, &nFileSize);
			if (!pFile)
				return 0;

			// Instance NT Headers
			PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pFile + ((PIMAGE_DOS_HEADER)pFile)->e_lfanew);
			if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
			PIMAGE_FILE_HEADER pFHdr = &pNtHdr->FileHeader;
			PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
			if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return FALSE;

			// Prepare Hashing
			cry::Md5 hash;
			// BCRYPT_ALG_HANDLE ah;
			// BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, NULL, NULL);
			// BCRYPT_HASH_HANDLE hh;
			// BCryptCreateHash(ah, &hh, NULL, 0, NULL, 0, NULL);

			for (uchar i = 0; i < pFHdr->NumberOfSections; i++) {
				// Instance Section and Check if Type is accepted
				PIMAGE_SECTION_HEADER pSHdr = ((PIMAGE_SECTION_HEADER)((ptr)pOHdr + (ptr)pFHdr->SizeOfOptionalHeader) + i);
				if (!((pSHdr->Characteristics & IMAGE_SCN_CNT_CODE) || (pSHdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)))
					continue;

				// Check for Special Section
				BOOLEAN bFlag;
				for (uchar j = 0; j < e_nSections; j++) {
					bFlag = TRUE;
					for (uchar n = 0; n < IMAGE_SIZEOF_SHORT_NAME; n++) {
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
				void* pSection = (void*)((ptr)pFile + (ptr)pSHdr->PointerToRawData);
				size_t nSection = pSHdr->SizeOfRawData;

				// Select what to to
				if (bFlag == 1) {
					void* pHash = 0;

					// TODO: replace with SigScanner
					// Find Hash Signature
					for (uint j = 0; j < nSection - sizeof(md5); j++) {
						bFlag = TRUE;
						for (uchar n = 0; n < sizeof(md5); n++) {
							if (((byte*)pSection)[j + n] != (*(byte**)&e_HashSig)[n]) {
								bFlag = FALSE;
								break;
							}
						} if (bFlag) {
							pHash = (void*)((ptr)pSection + j);
							break;
						}
					}

					// Hash only Data surrounding the Hash
					size_t nRDataP1 = (ptr)pHash - (ptr)pSection;
					hash.EHashData(pSection, nRDataP1);
					// BCryptHashData(hh, (uchar*)pSection, nRDataP1, NULL);
					size_t nRDataP2 = ((ptr)pSection + nSection) - ((ptr)pHash + sizeof(md5));
					hash.EHashData((void*)((ptr)pHash + sizeof(md5)), nRDataP2);
					// BCryptHashData(hh, (PUCHAR)((ptr)pHash + sizeof(hash)), nRDataP2, NULL);
				}
				else if (bFlag >= 2)
					continue;
				else
					hash.EHashData(pSection, nSection);
				// BCryptHashData(hh, (uchar*)pSection, nSection, NULL);
			}

			hash.EFnialize();
			bool bT = hash.pMd5 == e_HashSig;
			// void* pMd5 = malloc(sizeof(hash));
			// BCryptFinishHash(hh, (uchar*)pMd5, sizeof(hash), NULL);
			// BCryptDestroyHash(hh);
			// BCryptCloseAlgorithmProvider(ah, NULL);
			// BOOL bT = EMd5Compare(pMd5, e_HashSig);
			// free(pMd5);
			return bT;
		}

		/* { // Instance Section info code
			WORD wNOS = pFh->NumberOfSections;
			PIMAGE_SECTION_HEADER pSHdr = (PIMAGE_SECTION_HEADER)((ptr)pOh + pFh->SizeOfOptionalHeader);
			while (wNOS--) {
				if (!lstrcmpA(pSHdr->Name, ".reloc\0"))
					break;
				pSHdr++;
			}
			pSHdr->PointerToRelocations;
		} */


		/* How it should work:
		   Instance

		*/

		status IHashMappedSection() {
			HMODULE hMod = GetModuleHandle(nullptr);
			PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((ptr)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
			if (pNth->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
			PIMAGE_OPTIONAL_HEADER pOh = &pNth->OptionalHeader;
			if (pOh->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return FALSE;

			// Temporery
			int deltaReloc = (ptr)hMod - 0x40000;

			// DOESN'T WORK BECAUSE FUCK YOU ~PeLdr
			// Instance Relocationtable Dynamically
			// maybe i fucked up tho
			PIMAGE_BASE_RELOCATION pBr = (PIMAGE_BASE_RELOCATION)(pOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (ptr)hMod);
			struct IMAGE_RELOCATION_ENTRY {
				word Type : 4;
				word Offset : 16;
			} *pRe = (IMAGE_RELOCATION_ENTRY*)(pBr + 1);


			int headers = pOh->SizeOfHeaders / 0x1000;
			if (pOh->SizeOfHeaders % 0x1000)
				headers += 0x1000;
			void* pImageCopy = VirtualAlloc(nullptr, pOh->SizeOfImage - headers, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			PIMAGE_SECTION_HEADER pSh = IMAGE_FIRST_SECTION(pNth);
			for (char i = 0; i < pNth->FileHeader.NumberOfSections; i++) {




				pSh++;
			}



			while (pRe)

			return 0;
		}
	}

	// Prototype version that returns a functioPointer (just use void* and casts instead)
	// int (*ImportFunctionByHash2(geter paramenters))(functionpointer parameters) {}

	void* ImportFunctionByHash(
		_In_ const HMODULE hMod,
		_In_ const md5&    pHash
	) {
		PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((ptr)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (pNth->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		PIMAGE_OPTIONAL_HEADER pOh = &pNth->OptionalHeader;
		if (pOh->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return nullptr;
		if (pOh->NumberOfRvaAndSizes < 1)
			return nullptr;

		PIMAGE_EXPORT_DIRECTORY pEd = (PIMAGE_EXPORT_DIRECTORY)(pOh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ptr)hMod);
		PCSTR* pszNameTable = (PCSTR*)(pEd->AddressOfNames + (ptr)hMod);
		cry::Md5 hash;
		for (int i = 0; i < pEd->NumberOfNames; i++) {
			PCSTR sz = pszNameTable[i] + (ptr)hMod;
			hash.EHashData((void*)sz, strlen(sz));
			hash.EFnialize();

			if (hash.pMd5 == pHash) // <- i could just return GetProcAddress here, but the work to do it manually from here is minimal
				return (void*)(((size_t*)(pEd->AddressOfFunctions + (ptr)hMod))[((word*)(pEd->AddressOfNameOrdinals + (ptr)hMod))[i]] + (ptr)hMod);
		}

		return nullptr;
	}



	/* Thread Local Storage (TLS) Callback :
	   This will start the Protection Services
	   and partially initialize _riftldr       */
	static BOOLEAN l_bTlsFlag = TRUE;
	extern const byte e_IKey[24];
	VOID NTAPI ITlsCb(
		_In_ void* DllHandle,
		_In_ dword dwReason,
		_In_ void* Reserved
	) {
		UNREFERENCED_PARAMETER(DllHandle);
		UNREFERENCED_PARAMETER(dwReason);
		UNREFERENCED_PARAMETER(Reserved);
		if (l_bTlsFlag) {
			{	// Partially initialize PIB (Neccessary Fields only)
				g_PIB = (PIB*)malloc(sizeof(PIB)); // potentially unsafe
				// g_PIB = (PIB*)HeapAlloc(hPH, NULL, sizeof(PIB));
				// g_PIB->hPH = hPH;

				g_PIB->sMod.hM = GetModuleHandleW(NULL);
				GetModuleFileNameW(g_PIB->sMod.hM, g_PIB->sMod.szMFN, MAX_PATH);

				// TODO: smth like this
				// g_PIB->sCry.IK = new cry::Aes(e_IKey);
			}

			// img::IHashBinaryCheck();
			img::IHashMappedSection();

			void* a = ImportFunctionByHash(GetModuleHandleW(L"ntdll.dll"), *(md5*)"\x4b\xef\x63\xe1\x6e\x12\x8a\xd7\x75\x1a\x37\xda\x73\x9f\x19\x88");
			void* b = (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrCaptureTimeout");
			// Call Anit RE Methods here...
			// (Anti Debugger, Section Hashing, Function Hooking)

			l_bTlsFlag = FALSE;
		}
	}
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_TlsCallback")
#pragma data_seg(".CRT$XLB")
	extern "C" PIMAGE_TLS_CALLBACK TlsCallback = ITlsCb;
#pragma data_seg()
}