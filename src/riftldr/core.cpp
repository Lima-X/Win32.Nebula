#include "ldr.h"

#pragma region Startup-Loader
/* Thread-Local-Storage (TLS) Callback :
   This will start the Protection-Services,
   decrypt and unpack the actuall code
   and ensure code integrity. */
void __stdcall TlsCoreLoader(
	_In_ void* DllHandle,
	_In_ u32   dwReason,
	_In_ void* Reserved
) {
	UNREFERENCED_PARAMETER(DllHandle);
	UNREFERENCED_PARAMETER(Reserved);

	return;

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		{
			auto BaseAddress = (handle)GetModuleHandleW(nullptr);
			auto* NtHeader = utl::GetNtHeader(BaseAddress);
			const char ProtectedSections[4][8] = { ".nb0", ".nbr", ".nbw", ".nbx" };
		#ifdef _DEBUG
			// Simulate Inaccessable protected Sections by setting Pageprotections to NoAccess
			IMAGE_SECTION_HEADER* SectionPointers[4];
			dword OldSectionProtections[4];
			for (u8 i = 0; i < 4; i++) {
				SectionPointers[i] = utl::FindSection(NtHeader, ProtectedSections[i]);
				if (SectionPointers[i])
					VirtualProtect((void*)((ptr)SectionPointers[i]->VirtualAddress + (ptr)BaseAddress), SectionPointers[i]->Misc.VirtualSize,
						PAGE_NOACCESS, OldSectionProtections + i);
			}
		#endif

			auto Status = ValidateImportAddressTable(BaseAddress);

		#ifndef _DEBUG
			// Prevent rrror popups, we dont wanna let the user know if we crashed
			SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
		#endif

			// Setup ProcessCookie (required for CryptPointer)
			dword RtlState;
			g_.ProcessCookie = (u64)RtlRandomEx(&RtlState) << 32 | RtlRandomEx(&RtlState);
			g_.CookieOffset = RtlRandomEx(&RtlState) & 0x1f;

			// Initializing ServiceManager
			ServiceManager = new svc2;

			void SetupMemoryScanner();
			SetupMemoryScanner();


			poly Parameters[2];
			Parameters[0] = 23;
			Parameters[1] = 43;
			poly ret;
			auto a = ServiceManager->ServiceCall(0x21, &ret, (poly)Parameters);



			// cry::XPressH compressor;

			// Initialize

			/* Execution Plan:
			   1. Protect TLS (Stage-1):
				  - Hide Thread
				  - Basic debugger tests
				  - Check Systemcalls

			   2. Ensure integrity of the loaderstub (selfhashing (fnv1a64))

			   3. Start Protection-Services (Protect TLS Stage-2):
				  - MemoryScanner
				  - Test for Virtual Environment
				  - Run all Debugger Checks

			   4. Decrypt & unpack the core (per registered section):
				  - Undo Base-Relocations in region (fix corrupted data)
				  - Decrypt (rc4mod)
				  - Unpack (LZ77+Huffman (RtlDecompressBufferEx))
				  - Reapply Base-Relocations on section
				  - Ensure integrity of unpacked code/data (hashing (fnv1a64 per section))
			*/

			// Stage 4:
			wchar SystemDirectory[MAX_PATH];
			GetSystemDirectoryW(SystemDirectory, MAX_PATH);
			wchar BCryptDll[MAX_PATH];
			// ldr::GetSystemDllbyHash(SystemDirectory, N_BCRYPTDLL, BCryptDll);
			// handle BCry = LoadLibraryW(BCryptDll);
			// auto BCryptOpenAlgorithmProvider = (cry::bcryoap_t)utl::ImportFunctionByHash(BCry, N_BCOALGPRO);

			i64 BaseDelta = (i64)BaseAddress - 0x140000000;
			for (u8 i = 0; i < 4; i++) {
				auto Section = utl::FindSection(NtHeader, ProtectedSections[i]);
				if (!Section)
					continue;

				// Reverse Relocs (reverse damage done by Ldr to the protected sections)
				void* SectionAddress = (void*)((ptr)Section->VirtualAddress + (ptr)BaseAddress);
				dword OldProtection;
				VirtualProtect(SectionAddress, Section->Misc.VirtualSize, PAGE_READWRITE, &OldProtection);
				status SLdr = ldr::ApplyBaseRelocationsOnSection(BaseAddress, Section, nullptr, -BaseDelta);
				if (S_ERROR(SLdr))
					ExitProcess(SLdr);

				// Decrypt Data

				// Uncompress LZ77+Huffman

				// Reapply BaseRelocations
				ldr::ApplyBaseRelocationsOnSection(BaseAddress, Section, nullptr, BaseDelta);
			}

		#ifdef _DEBUG
			// Revert Pageprotections on Blocked Sections (this simulates a Successful decryption)
			for (u8 i = 0; i < 4; i++)
				if (SectionPointers[i]) {
					ptr address = ((ptr)SectionPointers[i]->VirtualAddress + (ptr)BaseAddress);
					size_t size = SectionPointers[i]->Misc.VirtualSize;

					dword OldProtection;
					VirtualProtect((void*)address, size, OldSectionProtections[i], &OldProtection);

					// VirtualProtect((void*)((ptr)SectionPointers[i]->VirtualAddress + BaseAddress), SectionPointers[i]->Misc.VirtualSize,
					//	OldSectionProtections[i], &OldProtection);
				}
		#endif
		} return;
	case DLL_PROCESS_DETACH:
		{

		} return;
	}
}
// ThreadLocalStorage datatemplate and reference table
EXTERN_C EXPORT const dword TlsLoaderConfiguation     = 0;
EXTERN_C EXPORT const byte  Nb0ProtectedSectionKey[8] = { 0 };
extern "C" {
	u32 _tls_index = 0;
	const PIMAGE_TLS_CALLBACK _tls_callback[] = {
		(PIMAGE_TLS_CALLBACK)TlsCoreLoader,
		(PIMAGE_TLS_CALLBACK)nullptr
	};

#pragma comment (linker, "/include:_tls_used")
	extern const IMAGE_TLS_DIRECTORY64 _tls_used = {
		(ptr)0, (ptr)0,      // tls data (unused)
		(ptr)&_tls_index,    // address of tls_index
		(ptr)&_tls_callback, // pointer to call back array
		(u32)0, (u32)0       // tls properties
	};
}
#pragma endregion

// New Service Dispatch System
#pragma region ServiceCenter
svc2::svc2() {
	m_DispatchTable = HeapCreate(null, HEAP_GENERATE_EXCEPTIONS, 0);
}
svc2::~svc2() {
	HeapDestroy(m_DispatchTable);
}

status svc2::SearchListForEntry(
	_In_  u64                     ServiceId,
	_Out_ FunctionDispatchEntry*& FunctionEntry
) {
	PROCESS_HEAP_ENTRY HeapEntry;
	HeapEntry.lpData = nullptr;

	HeapLock(m_DispatchTable);
	while (HeapWalk(m_DispatchTable, &HeapEntry))
		if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
			FunctionEntry = (FunctionDispatchEntry*)HeapEntry.lpData;
			if (FunctionEntry->FunctionId == ServiceId) {
				HeapUnlock(m_DispatchTable);
				return SUCCESS;
			}
		}
	HeapUnlock(m_DispatchTable);

	if (GetLastError() != ERROR_NO_MORE_ITEMS)
		return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
	return S_CREATE(SS_WARNING, SF_CORE, SC_NOT_FOUND);
}

status svc2::RegisterServiceFunction(
	_In_ u64                    FunctionId,
	_In_ ServiceFunctionPointer FunctionPointer
) {
	HeapLock(m_DispatchTable);

	// Test if ServiceId has been used already
	FunctionDispatchEntry* Entry;
	status Status = SearchListForEntry(FunctionId, Entry);
	if (S_CODE(Status) != SC_NOT_FOUND) {
		HeapUnlock(m_DispatchTable);
		return S_CREATE(SS_ERROR, SF_CORE, SC_ALREADY_EXISTS);
	}
	Status = SUCCESS;

	auto ServiceEntry = (FunctionDispatchEntry*)HeapAlloc(m_DispatchTable, 0, sizeof(FunctionDispatchEntry));

	// Associate Function to Module
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(FunctionPointer, &mbi, sizeof(mbi));
	void* ModuleBase = mbi.AllocationBase;
	if (*(word*)ModuleBase == IMAGE_DOS_SIGNATURE)
		ServiceEntry->ModuleAssociation = ModuleBase;
	else {
		ServiceEntry->ModuleAssociation = nullptr;
		Status = S_CREATE(SS_WARNING, SF_CORE, SC_SEARCH_UNSUCCESSFUL);
	}

	// Register function
	ServiceEntry->FunctionId = FunctionId;
	ServiceEntry->FunctionPointer = (ServiceFunctionPointer)utl::CryptPointer((ptr)FunctionPointer);
	HeapUnlock(m_DispatchTable);
	return Status;
}

status svc2::ServiceCall(            // Calls the requested servicefunction
	_In_     u64   ServiceId,        // identifier for the servicefunction
	_Out_    poly* ReturnValue,      // the result returned by the servicefunction
	_In_opt_ poly  ServiceParameters // A polymorpthic value to be passed throuh
) {
	// Search for Servicefunction and get its entry
	FunctionDispatchEntry* Entry;
	auto Status = SearchListForEntry(ServiceId, Entry);
	if (S_ISSUE(Status))
		return Status;

	// Call servicefunction and mutate pointer
	auto ServiceFunction = (ServiceFunctionPointer)utl::CryptPointer((poly)Entry->FunctionPointer);
	*ReturnValue = ServiceFunction(ServiceParameters);
	_InterlockedExchange64((long long*)&Entry->FunctionPointer, utl::CryptPointer((poly)ServiceFunction));

	return SUCCESS;
}
extern "C" status cCallService( // As in svc::ServiceCall
	_In_  u64   ServiceId,
	_Out_ poly* ReturnValue,
	_In_  poly  ServiceParameters
) {
	return ServiceManager->ServiceCall(ServiceId, ReturnValue, ServiceParameters);
}
#pragma endregion


N_PROTECTEDX status LoadPluginModule(
	_In_ const void* Module
) {
	// Map Image into Process, e.g.
	// handle mod = ldr.MapImage(Module, MEM_PRIVATE)

	// Run EntryPoint

	return 0;
}

#pragma region Core
N_PROTECTEDX i32 __cdecl CoreMain() {
	__try {
		*(char*)0x0 = 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		__debugbreak();
	}

	return SUCCESS;
}
#pragma endregion