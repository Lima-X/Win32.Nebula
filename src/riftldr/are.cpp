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
		return (handle)CodePointer((ptr)Region);
	}
	void RemoveMemoryRegionExclusion(
		_In_ handle MemoryExclusion
	) {
		HeapFree(m_ExclusionList, 0, (void*)CodePointer((poly)MemoryExclusion));
	}

private:
	status SearchListForExclusion(
		_In_      void*          VirtualAddress,
		_In_      size_t         RegionSize,
		_Out_opt_ MemoryRegion*& Region
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
	MemScan = (MemoryScan*)CodePointer((ptr)mscan);
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
		_In_ poly MemoryRegion
		) {
			auto mr = (poly*)MemoryRegion;
			return (poly)((MemoryScan*)CodePointer((ptr)MemScan))->
				AddMemoryRegionExclusion((void*)mr[0], (size_t)mr[1]);
		});
	ServiceManager->RegisterServiceFunction(N_REMEXCLUS, [](
		_In_ poly ExclusionReference
		) -> poly {
			((MemoryScan*)CodePointer((ptr)MemScan))->
				RemoveMemoryRegionExclusion(*(handle*)ExclusionReference);
			return 0;
		});
	ServiceManager->RegisterServiceFunction(N_SCANVASPC, [](
		poly Unused
		) -> poly {
			return ((MemoryScan*)CodePointer((ptr)MemScan))->ScanVirtualMemory();
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
		return (handle)CodePointer((ptr)Region);
	}
	void RemoveMemoryRegionExclusion(
		_In_ handle MemoryExclusion
	) {
		HeapFree(m_ExclusionList, 0, (void*)CodePointer((poly)MemoryExclusion));
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

		handle LdrModule = null;
		size_t ModuleSize = 0;

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


#pragma region Rc4Mod
// FIX: this shellcode was incorrect at the time of compiling, has ot be replaced
// src\scs\rc4mod.c : this is still raw and has to be obfuscated (done by the builder)
EXTERN_C EXPORT u8 NbRc4ModShellCode[] = {
	0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x4C,
	0x89, 0x74, 0x24, 0x20, 0x55, 0x48, 0x8D, 0x6C, 0x24, 0xF0, 0x48, 0x81, 0xEC, 0x10, 0x01, 0x00,
	0x00, 0x4D, 0x8B, 0xD1, 0x49, 0x8B, 0xC1, 0x49, 0xC1, 0xEA, 0x19, 0x4D, 0x8B, 0xF0, 0x48, 0xC1,
	0xE8, 0x2A, 0x48, 0x8B, 0xF2, 0x33, 0xDB, 0x44, 0x88, 0x55, 0x00, 0x44, 0x8B, 0xDB, 0x88, 0x45,
	0x01, 0x48, 0x8B, 0xF9, 0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x41, 0x0F, 0xB6, 0xC2, 0x44, 0x88, 0x1C, 0x04, 0x41, 0xFF, 0xC3, 0x44, 0x0F, 0xB6, 0x55, 0x00,
	0x41, 0xFE, 0xC2, 0x44, 0x88, 0x55, 0x00, 0x41, 0x81, 0xFB, 0x00, 0x01, 0x00, 0x00, 0x7C, 0xE0,
	0x4D, 0x8B, 0xD1, 0x4C, 0x8D, 0x04, 0x24, 0x49, 0xC1, 0xEA, 0x21, 0x41, 0x81, 0xE2, 0xFF, 0x01,
	0x00, 0x00, 0x8B, 0xC3, 0x4D, 0x8D, 0x40, 0x01, 0x33, 0xD2, 0xFF, 0xC3, 0x41, 0xF7, 0xF2, 0x48,
	0x63, 0xC2, 0x42, 0x0F, 0xB6, 0x0C, 0x30, 0x41, 0x02, 0x48, 0xFF, 0x0F, 0xB6, 0x45, 0x01, 0x02,
	0xC1, 0x88, 0x45, 0x01, 0x41, 0x0F, 0xB6, 0x48, 0xFF, 0x0F, 0xB6, 0xC0, 0x86, 0x0C, 0x04, 0x41,
	0x88, 0x48, 0xFF, 0x81, 0xFB, 0x00, 0x01, 0x00, 0x00, 0x7C, 0xC7, 0x49, 0x8B, 0xC1, 0x49, 0x8B,
	0xC9, 0x48, 0xC1, 0xE9, 0x11, 0x48, 0xC1, 0xE8, 0x32, 0x44, 0x0F, 0xB6, 0xD1, 0x66, 0x45, 0x85,
	0xC9, 0x74, 0x3D, 0x0F, 0x1F, 0x40, 0x00, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x41, 0x02, 0xC2, 0x49, 0xFF, 0xC9, 0x88, 0x45, 0x00, 0x0F, 0xB6, 0xD0, 0x0F, 0xB6, 0x04, 0x14,
	0x02, 0xC2, 0x0F, 0xB6, 0xC8, 0x88, 0x4D, 0x01, 0x0F, 0xB6, 0x14, 0x14, 0x86, 0x14, 0x0C, 0x0F,
	0xB6, 0x45, 0x00, 0x88, 0x14, 0x04, 0x0F, 0xB6, 0x45, 0x00, 0x66, 0x45, 0x85, 0xC9, 0x75, 0xD0,
	0x4C, 0x8B, 0xC6, 0x49, 0xC1, 0xE8, 0x20, 0x41, 0x0F, 0xB7, 0xC8, 0x48, 0x03, 0xF9, 0x66, 0x45,
	0x85, 0xC0, 0x74, 0x39, 0x41, 0xB9, 0xFF, 0xFF, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
	0x41, 0x02, 0xC2, 0x88, 0x45, 0x00, 0x0F, 0xB6, 0xD0, 0x0F, 0xB6, 0x04, 0x14, 0x02, 0xC2, 0x0F,
	0xB6, 0xC8, 0x88, 0x4D, 0x01, 0x0F, 0xB6, 0x14, 0x14, 0x86, 0x14, 0x0C, 0x0F, 0xB6, 0x45, 0x00,
	0x88, 0x14, 0x04, 0x0F, 0xB6, 0x45, 0x00, 0x66, 0x45, 0x03, 0xC1, 0x75, 0xD3, 0x85, 0xF6, 0x74,
	0x56, 0x0F, 0x1F, 0x40, 0x00, 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x41, 0x02, 0xC2, 0x48, 0x8D, 0x7F, 0x01, 0x88, 0x45, 0x00, 0x48, 0xFF, 0xCE, 0x0F, 0xB6, 0xD0,
	0x0F, 0xB6, 0x04, 0x14, 0x02, 0xC2, 0x0F, 0xB6, 0xC8, 0x88, 0x4D, 0x01, 0x0F, 0xB6, 0x14, 0x14,
	0x86, 0x14, 0x0C, 0x0F, 0xB6, 0x45, 0x00, 0x88, 0x14, 0x04, 0x0F, 0xB6, 0x55, 0x01, 0x0F, 0xB6,
	0x45, 0x00, 0x0F, 0xB6, 0x14, 0x14, 0x02, 0x14, 0x04, 0x0F, 0xB6, 0xCA, 0x0F, 0xB6, 0x14, 0x0C,
	0x30, 0x57, 0xFF, 0x85, 0xF6, 0x75, 0xB9, 0x4C, 0x8D, 0x9C, 0x24, 0x10, 0x01, 0x00, 0x00, 0x49,
	0x8B, 0x5B, 0x10, 0x49, 0x8B, 0x73, 0x18, 0x49, 0x8B, 0x7B, 0x20, 0x4D, 0x8B, 0x73, 0x28, 0x49,
	0x8B, 0xE3, 0x5D, 0xC3
};

/* Config Format:
   BBBBBBBB|BBBBBBBB | BBBBBBBBB | BBBBBBBB|BBBBBBBB | B | BBBBBBBBBBBBBBBB
   ctx.i :8 ctx.j :8 | keylen :9 | SBoxOff  OffsetBa |   | Zerorounds   :16

   Region Format:
   BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB | BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
   Offset relative to base      :32 | size of region               :32 */
#define CreateRc4Config(kl, i, j, Sbo, Ob, Zr)\
        (((u64)((kl) & 0x1ff) << 33) |\
        ((u64)((i) & 0xff) << 50) |\
        ((u64)((j) & 0xff) << 42) |\
        ((u64)((Sbo) & 0xff) << 25) |\
        ((u64)((Ob) & 0xff) << 17) |\
        ((u64)(Zr) & 0xffff))
#define CreateRc4Region(bo, rs)\
        (((u64)(bo) << 32) | (rs))

EXTERN_C EXPORT u64 NbRc4ModShellCodeKey = 0;
void Rc4Mod(

) {
	static volatile i32 rc4modscl = 0;

	// Unlock rc4mod Shellcode
	if (_InterlockedIncrement(&rc4modscl) == 1) {
		for (auto i = 0; i < sizeof(NbRc4ModShellCode); i++)
			NbRc4ModShellCode[i] = _rotl8(NbRc4ModShellCode[i], i & 0x3) ^ ((u8*)NbRc4ModShellCodeKey)[i & 0x7];
	}

	// cipher region
	typedef void(__x64call* rc4mod)( // Crypts a buffer with RC4 cipher (RC4 modification)
		_Inout_ void* Buffer,        // The input data to be crypted
		_In_    u64   Region,        // The area of the input to be ciphered
		_In_    void* Key,           // The key to be used in the encryption
		_In_    u64   Config         // describes how the algorithim is scheduled
		);

	// TODO: continue here




	// Lock rc4mod shellcode
	if (!_InterlockedDecrement(&rc4modscl)) {
		for (auto i = 0; i < sizeof(NbRc4ModShellCode); i++)
			NbRc4ModShellCode[i] = _rotr8(NbRc4ModShellCode[i] ^ ((u8*)NbRc4ModShellCodeKey)[i & 0x7], i & 0x3);
	}
}


#pragma endregion

DEPRECATED_STR("has been replaced by new 3 level ring system")
class InSectionProtector {
public:
	InSectionProtector(                    // Sets up the IPS service
		_In_ handle                Module, // The module that is associated to the section
		_In_ IMAGE_SECTION_HEADER& Section // The intermediate protected section to be registered
	) : m_Module(Module),
		m_Section(m_Section) {
		EncryptSection();
	}
	~InSectionProtector() { // Removes the IPS service
		if (m_CryptoEngine)
			delete m_CryptoEngine;
	}

	void DestroySection() { // Erases the section from memory permanently and destroyes
		RtlSecureZeroMemory((void*)(m_Section.VirtualAddress + (ptr)m_Module), m_Section.Misc.VirtualSize);
		if (m_CryptoEngine)
			delete m_CryptoEngine;
	}

	status DecryptSection() {
		AcquireSRWLockExclusive(&m_Lock);
		auto Value = _InterlockedIncrement(&m_DecryptedCounter);
		if (Value == 0) // Check for imporper usage (Lock will not be unlocked and API will therefore block on the next call)
			return S_CREATE(SS_ERROR, SF_CORE, SC_COUNTER_CORRUPTED);

		if (Value == 1) {
			auto Section = (void*)(m_Section.VirtualAddress + (ptr)m_Module);
			// m_CryptoEngine->crypt(Section, m_Section.Misc.VirtualSize, Section);
			delete m_CryptoEngine;
			m_CryptoEngine = nullptr;
		}

		ReleaseSRWLockExclusive(&m_Lock);
		return SUCCESS;
	}
	status EncryptSection() {
		AcquireSRWLockExclusive(&m_Lock);
		auto Value = _InterlockedDecrement(&m_DecryptedCounter);
		if (Value == -1ul) // Check for imporper usage (same as above)
			return S_CREATE(SS_ERROR, SF_CORE, SC_COUNTER_CORRUPTED);

		if (!Value) {
			// Create new provider with random key
			m_CryptoEngine = nullptr; // new rc4;
			u32 RtlState;
			byte RandomKey[256];
			for (auto i = 0; i < 256 / 4; i++)
				((u32*)RandomKey)[i] = RtlRandomEx(&RtlState);
			// m_CryptoEngine->ksa(RandomKey, 256);

			// Encrypt section and reschedule/reset key
			auto Section = (void*)(m_Section.VirtualAddress + (ptr)m_Module);
			// m_CryptoEngine->crypt(Section, m_Section.Misc.VirtualSize, Section);
			// m_CryptoEngine->ksa(RandomKey, 256);
		}

		ReleaseSRWLockExclusive(&m_Lock);
		return SUCCESS;
	}

private:
	const    handle                m_Module;
	const    IMAGE_SECTION_HEADER& m_Section;
	volatile u32                   m_DecryptedCounter = 0; // tracks the amount of decryption requests,
	                                                       // every decryption call must be matched by a encrypt call,
	                                                       // failing to do so will result in an error or leave the section readable.
	SRWLOCK m_Lock = SRWLOCK_INIT;                         // Cryptolock for thread safety
	u64*    m_CryptoEngine = nullptr;                      // rc4 crypto engine
};

class PageGuard {
	struct MemoryRegion {
		void*  VirtualAddress;
		size_t RegionSize;
	};

public:
	PageGuard()
	  : m_GuardPageList(DecodePointer(g_.NebulaHeap)),
		m_GuardCodeList(DecodePointer(g_.NebulaHeap)) {}

	status RegisterGuardedMemory(
		_In_ void* VirtualAddress,
		_In_ size_t RegionSize
	) {

	}
	status RegisterAllowedCode(
		_In_ void*  VirtualAddress,
		_In_ size_t RegionSize
	) {

	}


private:

	DoublyLinkedList m_GuardPageList;
	DoublyLinkedList m_GuardCodeList;
};