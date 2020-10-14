/* Most of the Code in this File gets executed before the CRT is initialized (TLS Callback),
   therefore the usage of CRT features "might" be unsafe.
   This basically means that everything in here is to be treated as unsafe/unstable
   and has the potential to cause unwanted behaviour such as crashes.
   (I guess thats what you get for abusing "undocumented" features :P)

   NOTE: As of v0.28 this will be isolated from the main programm as it has its own "entrypoint"
   and therefore should also be treated as technically its own programm.
   This means that everything in here is specifically made for here only
   and everything outside of this file should NOT be used here.
   Inoder to still communicate/inform the main ldr code, they will be linked through a small "interface" */

#include "antire.h"

namespace are { // Anti Reverse Engineering
	namespace dbg { // Anti Debugging/Debugger (Detection)
		static HMODULE hNtDll;

		// Do it manually, by reading the flag directly from the PEB
		static bool IBasicDebuggerCheck() {
			void* pPeb = (void*)__readfsdword(0x30);
			return *(byte*)((ptr)pPeb + 2);
		}

		// ICheckProcessDebugFlags will return true if
		// the EPROCESS->NoDebugInherit is == FALSE,
		// the reason we check for false is because
		// the NtQueryProcessInformation function returns the
		// inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
		static BOOL ICheckProcessDebugFlags() {
			// Much easier in ASM but C/C++ looks so much better
			// Get NtQueryInformationProcess
			typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, uint32, void*, ULONG, PULONG);
			pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

			dword NoDebugInherit;
			NTSTATUS nts = NtQIP(GetCurrentProcess(),
				0x1f, // ProcessDebugFlags
				&NoDebugInherit, 4, 0);
			if (!nts)
				return false;
			return !NoDebugInherit;
		}

		// This function uses NtQuerySystemInformation
		// to try to retrieve a handle to the current
		// process's debug object handle. If the function
		// is successful it'll return true which means we're
		// being debugged or it'll return false if it fails
		// or the process isn't being debugged
		static bool IDebugObjectCheck() {
			// Much easier in ASM but C/C++ looks so much better
			// Get NtQueryInformationProcess
			typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, uint32, void*, ULONG, PULONG);
			pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

			HANDLE hDebugObject;
			NTSTATUS nts = NtQIP(GetCurrentProcess(),
				0x1e, // ProcessDebugObjectHandle
				&hDebugObject, 4, 0);
			if (!nts)
				return false;
			return hDebugObject;
		}

		// EHideThread will attempt to use
		// NtSetInformationThread to hide a thread
		// from the debugger, Passing NULL for
		// hThread will cause the function to hide the thread
		// the function is running in. Also, the function returns
		// false on failure and true on success
		status EHideThread(
			_In_opt_ HANDLE hThread = NULL
		) {
			// Get NtSetInformationThread
			typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, uint32, void*, ULONG);
			pNtSetInformationThread fnNtSIT = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

			// Set the thread info
			NTSTATUS nts;
			if (!hThread)
				nts = fnNtSIT(GetCurrentThread(),
					0x11, // HideThreadFromDebugger
					0, 0);
			else
				nts = fnNtSIT(hThread, 0x11, 0, 0);
			return nts;
		}

		// ICheckOutputDebugString checks whether or
		// OutputDebugString causes an error to occur
		// and if the error does occur then we know
		// there's no debugger, otherwise if there IS
		// a debugger no error will occur
		static bool ICheckOutputDebugString() {
			SetLastError(0);
			OutputDebugStringW(L"dbgC");
			return GetLastError();
		}

		// The IInt2DCheck function will check to see if a debugger
		// is attached to the current process. It does this by setting up
		// SEH and using the Int 2D instruction which will only cause an
		// exception if there is no debugger. Also when used in OllyDBG
		// it will skip a byte in the disassembly and will create
		// some havoc.
		static bool IInt2DCheck() {
			__try {
				__asm {
					int 0x2d
					xor eax, eax
					add eax, 2
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return false;
			}

			return true;
		}

		// CheckCloseHandle will call CloseHandle on an invalid
		// dword aligned value and if a debugger is running an exception
		// will occur and the function will return true otherwise it'll
		// return false
		static bool ICheckCloseHandle() {
			__try {
				CloseHandle(INVALID_HANDLE_VALUE);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return true;
			}

			return false;
		}

		LONG WINAPI IUnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers) {
			// Restore old UnhandledExceptionFilter
			SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);

			// Skip the exception code
			pExcepPointers->ContextRecord->Eip += 2;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		void ISehUnhandledException() {
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
			CreateThread(0, 0, thAntiDebug, 0, 0, 0);
			return 0;
		}

		// nice another bad joke
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

	// All this shit is unsafe and idk how it didn't cause an issue yet,
	// because some code here should really cause problems
	namespace vma { // Virtual Machine Awareness
		// this has to be checked and fixed, its a terrible mess atm...
		static bool ICheckVMware() {
			__try {
				__asm {
					push ebx

					mov  eax, 'VMXh'
					mov  ebx, 0      // any value but not the MAGIC VALUE
					mov  ecx, 10     // get VMWare version
					mov  edx, 'VX'   // port number
					in   eax, dx     // read port

					pop  ebx
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return false;
			}

			return true;
		}

		static bool ICheckVirtualBox() {
			HANDLE hDevice = CreateFileW(L"\\\\.\\VBoxMiniRdrDN", GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hDevice != INVALID_HANDLE_VALUE) {
				CloseHandle(hDevice);
				return true;
			} else
				return false;
		}

		static dword ICVPCExceptionFilter(
			_In_ PEXCEPTION_POINTERS ep
		) {
			PCONTEXT pCt = ep->ContextRecord;
			pCt->Ebx = (dword)-1; // Not running VPC
			pCt->Eip += 4; // skip past the "call VPC" opcodes

			return EXCEPTION_EXECUTE_HANDLER; // we can safely resume execution since we skipped faulty instruction
		}
		static BOOL ICheckVirtualPC() {
			__try {
				__asm {
					push   ebx

					mov    ebx, 0 // Flag
					mov    eax, 1 // VPC function number
					// call VPC
					__emit 0Fh
					__emit 3Fh
					__emit 07h
					__emit 0Bh

					pop    ebx
				}
			} __except (ICVPCExceptionFilter(GetExceptionInformation())) {
				return FALSE;
			}

			return TRUE;
		}

		// wtf
		BOOL ICheckVmPresent() {
			BOOL bT = ICheckVMware();
			if (bT)	return TRUE;
			bT = ICheckVirtualBox();
			if (bT)	return TRUE;
			bT = ICheckVirtualPC();
			return bT;
		}
	}

	namespace dli { // Anti Dll(Module) Injection (Detection)
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

			// Get a list of all the modules in this process.
			dword nResult;
			BOOL bs = K32EnumProcessModules(hProcess, NULL, 0, &nResult);
			HMODULE* hMods = (HMODULE*)HeapAlloc(GetProcessHeap(), 0, nResult);
			bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
			if (bs)
				for (uchar i = 0; i < nResult / sizeof(HMODULE); i++) {
					WCHAR szModuleName[MAX_PATH];

					// Get the full path to the module's file.
					if (K32GetModuleFileNameExW(hProcess, hMods[i], szModuleName, MAX_PATH)) {

					}
				}

			HeapFree(GetProcessHeap(), 0, hMods);
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
				if (!wcsstr(lpLibFileName, l_AllowedLibraries[i])) //  <- should be case insensitive
					return RLoadLibraryW(lpLibFileName);
			return NULL;
		}
		static HMODULE(WINAPI* RLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ dword dwFlags) = LoadLibraryExW;
		HMODULE WINAPI HLoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ dword dwFlags) {
			for (uchar i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
				if (!wcsstr(lpLibFileName, l_AllowedLibraries[i]))
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

	namespace img { //  Image Tools
		DEPRECATED BOOL fnErasePeHeader() {
			// Get Nt Headers
			PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)GetModuleHandleW(nullptr);
			PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((ptr)pDosHdr + pDosHdr->e_lfanew);
			if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
			PIMAGE_OPTIONAL_HEADER pOHdr = &pNtHdr->OptionalHeader;
			if (pOHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return FALSE;

			dword dwProtect;
			size_t nOHdr = pOHdr->SizeOfHeaders;
			HANDLE hMod = GetModuleHandleW(nullptr);
			VirtualProtect(hMod, nOHdr, PAGE_EXECUTE_READWRITE, &dwProtect);
			SecureZeroMemory(hMod, nOHdr);
			VirtualProtect(hMod, nOHdr, dwProtect, &dwProtect);
			return TRUE;
		}


		// So this is quiet shitty for debugging, basically i just realized that the debugger works by replacing instructions
		// with int3 interrupts (0xcc), so this basically fucks up the calculations if run under a debugger.
		// (as a nice sideeffect this might also catch a debugger if it places breakpoints)
		// NOTE: This function is now in a working state and should be relatively safe to use.
		//       I would still use this function with care and validate its result as it might still contain several bugs,
		//       it contains only a few sanity checks and is more experimantal than anything.
		// DEV-NOTE: This function took so much from me, my sanity and probably more,
		//           there were so many bugs and so much trouble associated with this piece of code.
		//           If this function breaks hope you're not the one that has to fix it...
		status HashMappedSection(
			_Out_ cry::Md5::hash& md5
		) {
			// Get Mapped Memory Image
			HMODULE hMod = GetModuleHandleW(nullptr);
			PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((ptr)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
			if (pNth->Signature != IMAGE_NT_SIGNATURE)
				return -1; // Invalid Signature
			if (pNth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return -2; // Invalid Signature

			// Calculate relocation delta
			int32 nRelocDelta = pNth->OptionalHeader.ImageBase - 0x400000;

			// Prepare Hashing
			BCRYPT_ALG_HANDLE ah;
			status s = BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
			BCRYPT_HASH_HANDLE hh;
			s = BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, NULL);

			// Iterate over Sections
			PIMAGE_SECTION_HEADER pSh = IMAGE_FIRST_SECTION(pNth);
			for (uint8 i = 0; i < pNth->FileHeader.NumberOfSections; i++) {
			Redo:
				// Skip if Section is not code_seg or const_seg
				if (!(pSh->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA)))
					continue;
				{	// Skip if Section is recognized as an illegal Section
					static const char* szISeg[] = {
						".idata",
						".data",
						// ".reloc"
					};

					for (uint8 j = 0; j < sizeof(szISeg) / sizeof(*szISeg); j++) {
						byte cpy[8];
						uint8 len = strlen(szISeg[j]);
						memcpy(cpy, szISeg[j], len);
						memset(cpy + len, 0, 8 - len);
						if (!memcmp(pSh->Name, cpy, 8)) {
							i++;
							goto Redo;
						}
					}
				}

				// Make copy of mapped Section
				void* pImageCopy = VirtualAlloc(nullptr, pSh->Misc.VirtualSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				memcpy(pImageCopy, (void*)(pSh->VirtualAddress + pNth->OptionalHeader.ImageBase), pSh->Misc.VirtualSize);

				// Calculate the difference between the section base of the mapped and copied version
				int nMappingDelta = (ptr)pImageCopy - (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase);
				if (nRelocDelta) {
					PIMAGE_BASE_RELOCATION pBr = (PIMAGE_BASE_RELOCATION)(pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase);
					while ((ptr)pBr < ((pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pNth->OptionalHeader.ImageBase)
						+ pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
					) {
						if ((ptr)pBr->VirtualAddress >= pSh->VirtualAddress
							&& (ptr)pBr->VirtualAddress <= pSh->VirtualAddress + pSh->Misc.VirtualSize
						) {
							// First Relocation Entry
							const struct IMAGE_RELOCATION_ENTRY {
								word Offset : 12;
								word Type : 4;
							} *pRe = (IMAGE_RELOCATION_ENTRY*)(pBr + 1);

							// iterate over Relocation Entries and apply changes
							for (uint16 j = 0; j < (pBr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY); j++)
								switch (pRe[j].Type) {
								case IMAGE_REL_BASED_HIGHLOW:
									*(ptr*)(((pBr->VirtualAddress + pNth->OptionalHeader.ImageBase) + pRe[j].Offset) + nMappingDelta) -= nRelocDelta;
									break;
								case IMAGE_REL_BASED_ABSOLUTE:
									continue;
								default:
									VirtualFree(pImageCopy, 0, MEM_RELEASE);
									return -3; // Unknown reloc Type
								}
						}

						// Advance to next reloc Block
						*(ptr*)&pBr += pBr->SizeOfBlock;
					}
				}

				// Special Handling (make a list of pointers and sizes that will be ignored by checking if they are in the region)
				// (dont do it through section names (maybe use them es additional checks (probably not tho (has no actuall gains))))
				static const struct region {
					ptr VirtualAddress;
					size_t RegionSize;
				} list[] = {
					{ (ptr)&dat::hMemoryHash, sizeof(dat::hMemoryHash) }
				};

				// dynamical sorted array of regions inside sections
				region* pSortedList = nullptr;
				size_t nSortedList = 0;

				ptr pSmallestAddress = -1;
				for (uint8 j = 0; j < sizeof(list) / sizeof(*list); j++) {
					// Current smallest index with bigger element then last smallest element
					uint8 ci = -1; // set to invalid by default
					for (int n = 0; n < sizeof(list) / sizeof(*list); n++) {
						// Check if pointer is within the boundaries of the current section
						if (list[n].VirtualAddress >= pSh->VirtualAddress + pNth->OptionalHeader.ImageBase
							&& list[n].VirtualAddress + list[n].RegionSize <= (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + pSh->Misc.VirtualSize
						) {
							// Check if Sorted list is already valid
							if (pSortedList) {
								// Check if ci is still invalid
								if (ci != (unsigned int)-1) {
									// Check if current last ellement is bigger then current and that current is smaller then last selected
									if (list[n].VirtualAddress < list[ci].VirtualAddress && list[n].VirtualAddress > pSortedList[j - 1].VirtualAddress)
										ci = n;
								} else if (list[n].VirtualAddress > pSortedList[j - 1].VirtualAddress)
									ci = n;
							} else {
								if (list[n].VirtualAddress < pSmallestAddress)
									ci = n, pSmallestAddress = list[n].VirtualAddress;
							}
						}
					}

					// Check if the last element selected is valid and add it to the list
					if (ci != (uint8)-1) {
						if (pSortedList)
							pSortedList = (region*)HeapReAlloc(GetProcessHeap(), NULL, pSortedList, ++nSortedList * sizeof(*pSortedList));
						else
							pSortedList = (region*)HeapAlloc(GetProcessHeap(), NULL, ++nSortedList * sizeof(*pSortedList));

						pSortedList[j] = list[ci];
					} else
						break;
				}

				// Iterate through ignorelist and hash
				ptr pSection = (pSh->VirtualAddress + pNth->OptionalHeader.ImageBase);
				if (nSortedList) {
					for (uint8 j = 0; j < nSortedList; j++) {
						ptr dif = pSortedList[j].VirtualAddress - pSection;
						s = BCryptHashData(hh, (uchar*)(pSection + nMappingDelta), dif, NULL);
						pSection += dif + pSortedList[j].RegionSize;
					}
					s = BCryptHashData(hh, (uchar*)(pSection + nMappingDelta),
						((pSh->VirtualAddress + pNth->OptionalHeader.ImageBase) + pSh->Misc.VirtualSize) - pSection, NULL);
				} else
					s = BCryptHashData(hh, (uchar*)(pSection + nMappingDelta), pSh->Misc.VirtualSize, NULL);

				if (pSortedList)
					HeapFree(GetProcessHeap(), NULL, pSortedList);

				// TODO: just hashing the sections here
				VirtualFree(pImageCopy, 0, MEM_RELEASE);
				pSh++;
			}

			BCryptFinishHash(hh, (uchar*)&md5, sizeof(md5), NULL);
			BCryptDestroyHash(hh);
			BCryptCloseAlgorithmProvider(ah, NULL);
			return 0;
		}
	}

	// Prototype version that returns a functioPointer (just use void* and casts instead)
	// int (*ImportFunctionByHash2(geter paramenters))(functionpointer parameters) {}
	void* ImportFunctionByHash(
		_In_ const HMODULE         hMod,
		_In_ const cry::Md5::hash& pHash
	) {
		PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((ptr)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (pNth->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (pNth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return nullptr;

		PIMAGE_EXPORT_DIRECTORY pEd = (PIMAGE_EXPORT_DIRECTORY)
			(pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ptr)hMod);
		PCSTR* pszNameTable = (PCSTR*)(pEd->AddressOfNames + (ptr)hMod);

		BCRYPT_ALG_HANDLE ah;
		BCryptOpenAlgorithmProvider(&ah, BCRYPT_MD5_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG);
		BCRYPT_HASH_HANDLE hh;
		BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG);
		void* pRet = nullptr;
		for (int i = 0; i < pEd->NumberOfNames; i++) {
			PCSTR sz = pszNameTable[i] + (ptr)hMod;
			BCryptHashData(hh, (uchar*)sz, strlen(sz), NULL);
			cry::Md5::hash md5;
			BCryptFinishHash(hh, (uchar*)&md5, sizeof(md5), NULL);

			if (md5 == pHash) { // <- I could just return GetProcAddress here, but the work to do it manually from here is minimal
				pRet = (void*)(((size_t*)(pEd->AddressOfFunctions + (ptr)hMod))[((word*)(pEd->AddressOfNameOrdinals + (ptr)hMod))[i]] + (ptr)hMod);
				break;
			}
		}

		BCryptDestroyHash(hh);
		BCryptCloseAlgorithmProvider(ah, NULL);
		return pRet;
	}

	/* Thread Local Storage (TLS) Callback :
	   This will start the Protection Services
	   and partially initialize _riftldr       */
	static bool l_bTlsFlag = false;
	extern const byte e_IKey[24];
	VOID NTAPI ITlsCb(
		_In_ void* DllHandle,
		_In_ dword dwReason,
		_In_ void* Reserved
	) {
		UNREFERENCED_PARAMETER(DllHandle);
		UNREFERENCED_PARAMETER(dwReason);
		UNREFERENCED_PARAMETER(Reserved);
		if (!l_bTlsFlag) {
			::dbg::TracePoint("Executing TLS Callback: " __FUNCTION__);

			// img::IHashBinaryCheck();
			cry::Md5::hash md5;
			img::HashMappedSection(md5);
			bool b = memcmp(&md5, &dat::hMemoryHash, sizeof(cry::Md5::hash));

			// void* a = ImportFunctionByHash(GetModuleHandleW(L"ntdll.dll"), *(hash*)"\x4b\xef\x63\xe1\x6e\x12\x8a\xd7\x75\x1a\x37\xda\x73\x9f\x19\x88");
			// void* b = (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrCaptureTimeout");
			// Call Anit RE Methods here...
			// (Anti Debugger, Section Hashing, Function Hooking)

			l_bTlsFlag = true;
		}
	}
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_TlsCallback")
#pragma data_seg(".CRT$XLB")
	extern "C" PIMAGE_TLS_CALLBACK TlsCallback = ITlsCb;
#pragma data_seg()
}
