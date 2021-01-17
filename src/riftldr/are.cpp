#include "ldr.h"

#pragma region MemoryScanner
typedef _Must_inspect_result_ NTSTATUS(NTAPI * ntqvm_t)(
	_In_                                        HANDLE  ProcessHandle,
	_In_opt_                                    PVOID   BaseAddress,
	_In_                                        ULONG   MemoryInformationClass, // Always set to 0
	_Out_writes_bytes_(MemoryInformationLength) PVOID   MemoryInformation,
	_In_                                        SIZE_T  MemoryInformationLength,
	_Out_opt_                                   PSIZE_T ReturnLength
);

class MemoryScan {
	struct MemoryRegion {
		void*  VirtualAddress;
		size_t RegionSize;
	};

public:
	MemoryScan() {
		m_ExclusionList = HeapCreate(0, 0, 0);
	}
	~MemoryScan() {
		HeapDestroy(m_ExclusionList);
	}

	status ScanUserModeVirtualMemory() {
		void* Iterator = nullptr;
		auto SuspiciousRegionCount = 0;

		auto NtQueryVirtualMemory = (ntqvm_t)ldr::ImportFunctionByHash(
			ldr::GetModuleHandleByHash(N_NTDLL), N_NTQUERYVM);

		// Enumerate all Usermode Memory
		while ((ptr)Iterator < ((ptr)1 << 48)) {
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(Iterator, &mbi, sizeof(mbi));

			if (mbi.State == MEM_COMMIT) {
				if (mbi.Protect & 0b11110001) { // Suspicious page protections (executable / noaccess)
					// Check if found region is within an exclusion
					MemoryRegion* mreg;
					auto Status = SearchListForExclusion(mbi.BaseAddress, mbi.RegionSize, mreg);
					if (S_CODE(Status) == SC_NOT_FOUND) {
						// Region is not within an exclusion,
						SuspiciousRegionCount++;
						TracePoint(DBG_WARNING, "Unknown executable region found!\n"
							"Address/Size: 0x%016llx / 0x%08x\n"
							"Protect: %08x, AllocProt: %08x ",
							mbi.BaseAddress, mbi.RegionSize,
							mbi.Protect, mbi.AllocationProtect);
					}
				}
			}

			(ptr&)Iterator += mbi.RegionSize;
		}

		if (SuspiciousRegionCount)
			return S_CREATEM(SuspiciousRegionCount);
		return SUCCESS;
	}

	handle AddMemoryRegionExclusion(
		_In_ void*  VirtualAddress,
		_In_ size_t RegionSize
	) {
		HeapLock(m_ExclusionList);
		auto Region = (MemoryRegion*)HeapAlloc(m_ExclusionList, 0, sizeof(MemoryRegion));
		*Region = { VirtualAddress, RegionSize };
		HeapUnlock(m_ExclusionList);
		return utl::CodePointer(Region);
	}
	void RemoveMemoryRegionExclusion(
		_In_ handle MemoryExclusion
	) {
		HeapFree(m_ExclusionList, 0, utl::CodePointer(MemoryExclusion));
	}

private:
	status SearchListForExclusion(
		_In_  void*          VirtualAddress,
		_In_  size_t         RegionSize,
		_Out_ MemoryRegion*& Region,
		_In_  bool           Reserved = 0
	) {
		PROCESS_HEAP_ENTRY HeapEntry;
		HeapEntry.lpData = nullptr;

		HeapLock(m_ExclusionList);
		while (HeapWalk(m_ExclusionList, &HeapEntry))
			if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
				Region = (MemoryRegion*)HeapEntry.lpData;

				// Check if the region searched for is within an exclusion
				if (Region->VirtualAddress < VirtualAddress &&
					(ptr)Region->VirtualAddress + Region->RegionSize > (ptr)VirtualAddress + RegionSize) {
					HeapUnlock(m_ExclusionList);
					return SUCCESS;
				}
			}
		HeapUnlock(m_ExclusionList);

		if (GetLastError() != ERROR_NO_MORE_ITEMS)
			return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
		return S_CREATE(SS_WARNING, SF_CORE, SC_NOT_FOUND);
	}

	handle m_ExclusionList;
};
handle MemScan;

// Thunks for servicemanager
poly AddMemoryRegionExclusion(
	poly ParameterList
) {
	return (poly)((MemoryScan*)utl::CodePointer(MemScan))->AddMemoryRegionExclusion(
		(void*)((poly*)ParameterList)[0], (size_t)((poly*)ParameterList)[1]);
}
poly RemoveMemoryRegionExclusion(
	poly ParameterList
) {
	((MemoryScan*)utl::CodePointer(MemScan))->RemoveMemoryRegionExclusion(
		*(handle*)ParameterList);
	return 0;
}
poly ScanUserModeVirtualMemory(
	poly ParameterList
) {
	return ((MemoryScan*)utl::CodePointer(MemScan))->ScanUserModeVirtualMemory();
}

void SetupMemoryScanner() {
	auto mscan = new MemoryScan;
	MemScan = utl::CodePointer(mscan);
	status s;

	// Add memoryscanner-services
	ServiceMgr->RegisterServiceFunction(N_ADDEXCLUS, AddMemoryRegionExclusion);
	ServiceMgr->RegisterServiceFunction(N_REMEXCLUS, RemoveMemoryRegionExclusion);
	ServiceMgr->RegisterServiceFunction(N_SCANVASPC, ScanUserModeVirtualMemory);

	// Add all loaded modules to exclusion list
	auto InMemoryOrderModuleList = ldr::GetModuleList();
	auto ListIterator = InMemoryOrderModuleList;
	while (ListIterator->Flink != InMemoryOrderModuleList) {
		ListIterator = ListIterator->Flink;

		auto VirtualAddress = (void*)((ptr)ListIterator + 0x20);
		auto RegionSize = (size_t)((ptr)ListIterator + 0x30);
		mscan->AddMemoryRegionExclusion(VirtualAddress, RegionSize);
	}

	// Test scan memory
	s = mscan->ScanUserModeVirtualMemory();

	// Safe internal encode pointer
	return;
}
#pragma endregion

status ValidateImportAddressTable( // Validates that the functionpointer thunks in the IAT actually point to the memory
                                   // inside the dll that is referenced by the import descriptor and therefor check if
                                   // if the IAT has been messed with like a IAT-Hook
	_In_ handle Module             // The Module whose IAT is to be validated for correctness
) {
	// Get start of importdata, aka the first import descriptor
	auto NtHeader = utl::GetNtHeader(Module);
	if (!NtHeader)
		return S_CREATE(SS_ERROR, SF_CORE, SC_INVALID_SIGNATURE);
	ptr BaseAddress = (ptr)Module;
	auto ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + BaseAddress);

	// Iterate over all Dll imports
	while (ImportDescriptor->OriginalFirstThunk) {
		auto DllBaseName = (char*)((ptr)ImportDescriptor->Name + BaseAddress);
		auto NameLength = strlen(DllBaseName);

		handle LdrModule;
		size_t ModuleSize;

		{	// Search for the Dll loaderdata inside the PEB
			auto InMemoryOrderModuleList = ldr::GetModuleList();
			auto ListIterator = InMemoryOrderModuleList;
			while (ListIterator->Flink != InMemoryOrderModuleList) {
			NextIteration:
				ListIterator = ListIterator->Flink;
				auto LdrDllName = (UNICODE_STRING*)((ptr)ListIterator + 0x48); // Get DllBaseName

				if (LdrDllName->Length / 2 == NameLength) {
					for (auto i = 0; i < NameLength; i++)
						if (tolower((char)LdrDllName->Buffer[i]) != tolower(DllBaseName[i]))
							goto NextIteration;

					LdrModule = *(handle*)((ptr)ListIterator + 0x20); // Get DllBaseAddress
					ModuleSize = *(size_t*)((ptr)ListIterator + 0x30); // Get SizeOfImage
					break; // Breaks out of the loader module enumeration
				}
			}
		}

		// Check if All import thunks are within this module
		auto ImportAddressTable = (ptr*)(ImportDescriptor->FirstThunk + BaseAddress);
		for (auto i = 0; ImportAddressTable[i]; i++)
			// TODO/BUG: This condition fails if the imported function is a forwarder
			if (ImportAddressTable[i] <= (ptr)LdrModule ||
				ImportAddressTable[i] >= (ptr)LdrModule + ModuleSize) {
				// Perform additional Check to validate that this import is wanted



				return S_CREATEM(i);
			}

		ImportDescriptor++;
	}

	return SUCCESS;
}
