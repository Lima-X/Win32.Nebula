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
		m_ExclusionList = HeapCreate(0, HEAP_GENERATE_EXCEPTIONS, 0);
	}
	~MemoryScan() {
		HeapDestroy(m_ExclusionList);
	}

	status ScanVirtualMemory() {
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
		return (handle)utl::CryptPointer((ptr)Region);
	}
	void RemoveMemoryRegionExclusion(
		_In_ handle MemoryExclusion
	) {
		HeapFree(m_ExclusionList, 0, (void*)utl::CryptPointer((poly)MemoryExclusion));
	}

private:
	status SearchListForExclusion(
		_In_  void*          VirtualAddress,
		_In_  size_t         RegionSize,
		_Out_ MemoryRegion*& Region
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

void SetupMemoryScanner() {
	auto mscan = new MemoryScan;
	MemScan = (MemoryScan*)utl::CryptPointer((ptr)mscan);
	status s;

	// Add all loaded modules to exclusion list
	// TODO: only add executable sections
	auto InMemoryOrderModuleList = ldr::GetModuleList();
	auto ListIterator = InMemoryOrderModuleList;
	while (ListIterator->Flink != InMemoryOrderModuleList) {
		ListIterator = ListIterator->Flink;

		auto VirtualAddress = (void*)((ptr)ListIterator + 0x20);
		auto RegionSize = (size_t)((ptr)ListIterator + 0x30);
		mscan->AddMemoryRegionExclusion(VirtualAddress, RegionSize);
	}

	// Add memoryscanner-services (Thunks for servicemanager)
	ServiceManager->RegisterServiceFunction(N_ADDEXCLUS, [](
		_In_ poly Region
		) {
			return (poly)((MemoryScan*)utl::CryptPointer((ptr)MemScan))->AddMemoryRegionExclusion(
				(void*)((poly*)Region)[0], (size_t)((poly*)Region)[1]);
		});
	ServiceManager->RegisterServiceFunction(N_REMEXCLUS, [](
		_In_ poly ExclusionReference
		) -> poly {
			((MemoryScan*)utl::CryptPointer((ptr)MemScan))->RemoveMemoryRegionExclusion(
				*(handle*)ExclusionReference);
			return 0;
		});
	ServiceManager->RegisterServiceFunction(N_SCANVASPC, [](
		poly Unused
		) -> poly {
			return ((MemoryScan*)utl::CryptPointer((ptr)MemScan))->ScanVirtualMemory();
		});

	// Test scan memory
	s = mscan->ScanVirtualMemory();
}
#pragma endregion

#pragma region MemoryIntegrity
class IntegrityScan {
	struct MemoryRegion {
		void* VirtualAddress;
		size_t RegionSize;
	};

public:
	IntegrityScan() {
		m_ExclusionList = HeapCreate(null, HEAP_GENERATE_EXCEPTIONS, 0);
	}
	~IntegrityScan() {
		HeapDestroy(m_ExclusionList);
	}


#define CI_DONT_BREAK_OUT_ON_ERROR  0x00000001 // continues on normaly but increments a internal counter for raised suspicions
#define CI_VERIFY_VIRTUALSECTIONEND 0x00000002 // verifies that the data behind the virtual end of the section is zeropadded (prevent hijacking)
#define CI_COMPARE_WITH_DISKIMAGE   0x00000004 // Compares the section in memory with the section of the file on disk (file associated by Module)
#define CI_RELOCATE_IMAGE_TO_BASE   0x00000008 // function will relocate the section to the default loadaddress and reapply relocs when finished
#define CI_OUT_OF_PLACE_VALIDATION  0x00000010 // prevents the function from doing shit that would modify data inplace
#define CI_IGNORE_EXCLUDED_REGIONS  0x00000020 // uses the exclusion list in order to avoid hashing data that might have been modified
#define CI_
	status CheckIntegrityOfSection(
		_In_     handle               Module,
		_In_     IMAGE_SECTION_HEADER Section,
		_In_     u64& Hash,
		_In_opt_ u32                  Options
	) {
		auto SuspiciousDataCounter = 0;
		status ReturnValue = SUCCESS;

		auto Address = (void*)((ptr)Section.VirtualAddress + (ptr)Module);
		size_t SectionSize = Section.Misc.VirtualSize;



		if (Options & CI_DONT_BREAK_OUT_ON_ERROR && SuspiciousDataCounter)
			return S_CREATEM(SuspiciousDataCounter);
		return SUCCESS;
	}



	handle AddMemoryRegionExclusion(
		_In_ void* VirtualAddress,
		_In_ size_t RegionSize
	) {
		HeapLock(m_ExclusionList);
		auto Region = (MemoryRegion*)HeapAlloc(m_ExclusionList, 0, sizeof(MemoryRegion));
		*Region = { VirtualAddress, RegionSize };
		HeapUnlock(m_ExclusionList);
		return (handle)utl::CryptPointer((ptr)Region);
	}
	void RemoveMemoryRegionExclusion(
		_In_ handle MemoryExclusion
	) {
		HeapFree(m_ExclusionList, 0, (void*)utl::CryptPointer((poly)MemoryExclusion));
	}

private:
	status ValidateSectionEnd(
		_In_ handle               Module,
		_In_ IMAGE_SECTION_HEADER Section

	) {
		auto Address = (void*)((ptr)Section.VirtualAddress + (ptr)Module);
		size_t SectionSize = Section.Misc.VirtualSize;

		// Check there hasnt been attached more data after the virtual end of the section
		auto SectionVirtualEnd = (byte*)((ptr)Address + SectionSize);
		auto SectionEnd = (byte*)utl::RoundUpToMulOfPow2((u64)SectionVirtualEnd, PAGE_SIZE);

		while (SectionVirtualEnd < SectionEnd)
			// Checks if byte is not null
			if (*SectionVirtualEnd++) {
				TracePoint(DBG_WARNING, "Suspicious byte found after virtual section end:\n0x%016llx [0x%02x]",
					SectionVirtualEnd - 1, *(SectionVirtualEnd - 1));
				return S_CREATE(SS_WARNING, SF_CORE, SC_UNKNOWN_DATA_FOUND);
			}
	}



	status SearchListForNearestExclusion(    // Searches the exclusionlist for the nearest memory region
											 // starting from VirtualAddress with in the specified region
		_In_  void*          VirtualAddress, // the start of the region to search
		_In_  size_t         RegionSize,     // the size of the region to search
		_Out_ MemoryRegion*& Region          // RefToPointer to be set to the nearest found region
											 // (set to 0 if no element was found)
	) {
		PROCESS_HEAP_ENTRY HeapEntry;
		HeapEntry.lpData = nullptr;
		Region = nullptr;

		HeapLock(m_ExclusionList);
		while (HeapWalk(m_ExclusionList, &HeapEntry))
			if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
				MemoryRegion* RegionEntry = (MemoryRegion*)HeapEntry.lpData;

				// Check if the region searched for is within an exlcusion
				if (RegionEntry->VirtualAddress < VirtualAddress &&
					(ptr)RegionEntry->VirtualAddress + RegionEntry->RegionSize >(ptr)VirtualAddress + RegionSize) {

					// Check if region is the closest to the currect location (VirtualAddress)
					if (!Region)
						Region = RegionEntry;
					else if ((ptr)RegionEntry->VirtualAddress - (ptr)VirtualAddress <
						(ptr)Region->VirtualAddress - (ptr)VirtualAddress)
						Region = RegionEntry;
				}
			}
		HeapUnlock(m_ExclusionList);

		if (GetLastError() != ERROR_NO_MORE_ITEMS)
			return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
		if (!Region)
			return S_CREATE(SS_WARNING, SF_CORE, SC_NOT_FOUND);
		return SUCCESS;
	}

	handle m_ExclusionList;
};
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

	auto SuspicousImportCounter = 0;

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
				// Perform reverse image search to validate wanted forwarder:
				// 1. Obtain info about the suspicous pointer (Name, and belonging module)
				// 2. Search for the export in the belonging module and check if addresses are equal

				auto ImportLookupTable = (u64*)(ImportDescriptor->OriginalFirstThunk + BaseAddress);
				void* Export;
				if (!(ImportLookupTable[i] & 1ull << 63))
					Export = (void*)((ImportLookupTable[i] + 2) + BaseAddress);
				else
					Export = (void*)ImportLookupTable[i];

				// TODO: use private GetProcAddress Implementation
				auto TargetFunction = (ptr)GetProcAddress((HMODULE)LdrModule, (LPCSTR)Export);
				if (TargetFunction == ImportAddressTable[i])
					continue;

				TracePoint(DBG_WARNING, "Suspicous Import found at: 0x016llx", ImportAddressTable[i]);
				SuspicousImportCounter++;
			}

		ImportDescriptor++;
	}

	if (SuspicousImportCounter)
		return S_CREATEM(SuspicousImportCounter);
	return SUCCESS;
}
