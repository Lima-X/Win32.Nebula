// Collection of Utility Functions
#include "shared.h"

namespace utl {
	IMAGE_NT_HEADERS* GetNtHeader(
		_In_ handle Module
	) {
		if (((IMAGE_DOS_HEADER*)Module)->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr; // Invalid signature

		IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)Module + ((IMAGE_DOS_HEADER*)Module)->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr; // Invalid signature
		if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return nullptr; // Invalid signature

		return NtHeader;
	}

	IMAGE_SECTION_HEADER* FindSection(
		_In_ IMAGE_NT_HEADERS* NtHeader,
		_In_ const char        Name[8]
	) {
		// Iterate over sections
		IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (u8 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
			if (*(qword*)SectionHeader->Name == *(qword*)Name)
				return SectionHeader;

			SectionHeader++;
		}

		return nullptr;
	}

	// GS:0x60(void*) -> PEB Linear Address
	// PEB:LoaderData(void*)                                    @ offset 0x18 (x64)
	// PEB_LDR_DATA:InMemoryOrderModuleList(LIST_ENTRY)         @ offset 0x20 (x64)
	// LDR_DATA_TABLE_ENTRY:InMemoryOrderModuleList(LIST_ENTRY) @ offset 0x10 (x64)
	// LDR_DATA_TABLE_ENTRY:DllBase(void*)                      @ offset 0x30 (x64)
	// LDR_DATA_TABLE_ENTRY:BaseDllName(UNICODE_STRING)         @ offset 0x58 (x64)
	LIST_ENTRY* GetModuleList() {
		auto PEB = (void*)__readgsqword(0x60);        // Get PEB
		auto LoaderData = (void*)((ptr)PEB + 0x18);   // Get PEB:LoaderDara
		LoaderData = *(void**)LoaderData;             // Get Linear Address of LoaderData
		return (LIST_ENTRY*)((ptr)LoaderData + 0x20); // Get List
	}
	handle GetModuleHandleThroughPeb(
		_In_ const wchar* ModuleName
	) {
		auto InMemoryOrderModuleList = GetModuleList();
		auto ListIterator = InMemoryOrderModuleList;
		while (ListIterator->Flink != InMemoryOrderModuleList) {
			ListIterator = ListIterator->Flink;

			auto DllName = (UNICODE_STRING*)((ptr)ListIterator + 0x48); // Get DllBaseName
			auto ModuleNameSize = nrt::wcslen(ModuleName) * sizeof(*ModuleName);
			if (DllName->Length == ModuleNameSize)
				if (RtlCompareMemory(DllName->Buffer, ModuleName, ModuleNameSize) == ModuleNameSize)
					return (handle)((ptr)ListIterator + 0x20); // Get DllBaseAddress
		}

		return nullptr;
	}
	handle GetModuleHandleByHash(
		_In_ fnv Hash
	) {
		wchar Buffer[MAX_PATH];
		UNICODE_STRING LowerName = { 0, MAX_PATH, Buffer };

		LIST_ENTRY* InMemoryOrderModuleList = GetModuleList();
		LIST_ENTRY* ListIterator = InMemoryOrderModuleList;
		while (ListIterator->Flink != InMemoryOrderModuleList) {
			ListIterator = ListIterator->Flink;

			auto DllName = (UNICODE_STRING*)((ptr)ListIterator + 0x48); // Get DllBaseName
			RtlDowncaseUnicodeString(&LowerName, DllName, false);
			if (FNV1aHash(LowerName.Buffer, DllName->Length) == Hash)
				return (handle)((ptr)ListIterator + 0x20); // Get DllBaseAddress
		}

		return nullptr;
	}

	void* ImportFunctionByHash(
		_In_ const handle Module,
		_In_ const fnv    Hash
	) {
		auto NtHeader = GetNtHeader(Module);
		if (!NtHeader)
			return nullptr;

		auto ModuleBase = (ptr)Module;
		auto ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)
			((ptr)NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ModuleBase);
		auto ppNameTable = (dword*)((ptr)ExportDirectory->AddressOfNames + ModuleBase);

		for (u32 i = 0; i < ExportDirectory->NumberOfNames; i++) {
			auto FunctionName = (const char*)((ptr)ppNameTable[i] + ModuleBase);
			auto InternalHash = FNV1aHash((void*)FunctionName, nrt::strlen(FunctionName));

			if (InternalHash == Hash) {
				auto OrdinalTable = (word*)((ptr)ExportDirectory->AddressOfNameOrdinals + ModuleBase);
				auto FunctionTable = (dword*)((ptr)ExportDirectory->AddressOfFunctions + ModuleBase);
				return (void*)((ptr)FunctionTable[OrdinalTable[i]] + ModuleBase);
			}
		}

		return nullptr; // No matching import found
	}

	#undef SearchPath            // Because WinAPI
	status GetSystemDllbyHash(   // Locates a system Dll by hash
		_In_  wchar* SearchPath, // The Path to search for a matching dll
		_In_  fnv    Hash,       // The hash of teh DllBaseName (Lowercase hash)
		_Out_ wchar* Path        // A buffer the full path of a matching dll will be written to
	) {
		typedef wchar* (__cdecl* wcscat_t)(
			_Inout_z_       wchar* strDestination,
			_In_z_    const wchar* strSource
			);

		handle NT = GetModuleHandleByHash(N_NTDLL);
		wcscat_t wcscat = (wcscat_t)ImportFunctionByHash(NT, N_CRTWCSCAT);

		wchar InternalPath[MAX_PATH];
		__movsb((byte*)InternalPath, (byte*)SearchPath, (nrt::wcslen(SearchPath) + 1) * sizeof(wchar));
		wcscat(InternalPath, L"\\*.dll");

		typedef wchar* (__cdecl*wcslwr_t)(
			wchar* str
			);
		wcslwr_t _wcslwr = (wcslwr_t)ImportFunctionByHash(NT, N_CRTWCSLWR);

		WIN32_FIND_DATAW fd;
		HANDLE hFind = FindFirstFileW(InternalPath, &fd);
		if (hFind == INVALID_HANDLE_VALUE)
			return S_CREATE(SS_ERROR, SF_NULL, SC_INVALID_HADNLE);
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				_wcslwr(fd.cFileName);
				if (FNV1aHash(fd.cFileName, nrt::wcslen(fd.cFileName) * sizeof(wchar)) == Hash) {
					__movsb((byte*)Path, (byte*)SearchPath, (nrt::wcslen(SearchPath) + 1) * sizeof(wchar));
					wcscat(Path, L"\\");
					wcscat(Path, fd.cFileName);
					return SUCCESS;
				}
			}
		} while (FindNextFileW(hFind, &fd));

		return SUCCESS;
	}

	status ApplyBaseRelocationsOnSection(              // Applies Relocations on a Addressrange
		_In_     handle                Module,         // BaseAddress of the Module from which the .reloc section should be used from
		_In_     IMAGE_SECTION_HEADER* Section,        // A pointer to the sectionheader of which to apply the relocs
		_In_opt_ void*                 Address,        // The Address at which the relocations should be applied at (if null relocs will be applied to mapped image of BaseAddress)
		_In_     i64                   RelocationDelta // The pointerdelta that should be applied
	) {
		auto NtHeader = GetNtHeader(Module);
		auto BaseRelocations = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!Section)
			return S_CREATE(SS_ERROR, SF_NULL, SC_INVALID_PARAMETER);

		// Delta between the map at which to apply the relocs if used and the mapped image
		i64 MappingDelta = Address ? (i64)Address - ((i64)Section->VirtualAddress + (i64)Module) : 0;
		auto Iterator = (IMAGE_BASE_RELOCATION*)((ptr)BaseRelocations->VirtualAddress + (ptr)Module);

		while ((ptr)Iterator < (ptr)BaseRelocations + BaseRelocations->Size) {
			// Check if Iterator is withing bounds of the selected region
			if (Iterator->VirtualAddress >= Section->VirtualAddress &&
				Iterator->VirtualAddress < Section->VirtualAddress + Section->Misc.VirtualSize) {
				// First Relocation Entry
				const struct IMAGE_RELOCATION_ENTRY {
					word Offset : 12;
					word Type : 4;
				} *RelocationEntry = (IMAGE_RELOCATION_ENTRY*)(BaseRelocations + 1);

				// Iterate over Relocation Entries and apply changes
				ptr RelocationPage = (ptr)BaseRelocations->VirtualAddress + (ptr)Module;
				for (u16 j = 0; j < (Iterator->SizeOfBlock - sizeof(*BaseRelocations)) / sizeof(IMAGE_RELOCATION_ENTRY); j++)
					switch (RelocationEntry[j].Type) {
					case IMAGE_REL_BASED_HIGHLOW:
						{
							ptr RelocationAddress = RelocationPage + RelocationEntry[j].Offset;
							*(ptr*)(RelocationAddress + MappingDelta) += RelocationDelta;
							break;
						}
					case IMAGE_REL_BASED_ABSOLUTE:
						continue;
					default:
						return S_CREATE(SS_ERROR, SF_NULL, SC_UNSUPPORTED); // Unknown reloc Type
					}
			}

			// Advance to next reloc Block
			(ptr&)Iterator += Iterator->SizeOfBlock;
		}

		return SUCCESS;
	}

	constexpr fnv FNV1aHash( // Generates a 64-Bit wide FNV-1a hash
		_In_ void*  Data,    // Pointer to data to hash
		_In_ size_t Size     // Size of data to hash in bytes
	) {
		fnv Hash = 0xcbf29ce484222325;
		while (Size--)
			Hash = (Hash ^ *((byte*&)Data)++) * 0x00000100000001b3;
		return Hash;
	}
}
