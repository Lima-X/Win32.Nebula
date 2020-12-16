// Collection of Utility Functions
#include "shared.h"

namespace utl {
	namespace img {
		IMAGE_NT_HEADERS* GetNtHeader(
			_In_ HMODULE hMod
		) {
			if (((IMAGE_DOS_HEADER*)hMod)->e_magic != IMAGE_DOS_SIGNATURE)
				return nullptr; // Invalid signature

			IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)hMod + ((IMAGE_DOS_HEADER*)hMod)->e_lfanew);
			if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
				return nullptr; // Invalid signature
			if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return nullptr; // Invalid signature

			return NtHeader;
		}

		IMAGE_SECTION_HEADER* FindSection(
			_In_ IMAGE_NT_HEADERS* NtHeader,
			_In_ const byte        Name[8]
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

		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;
		// GS:0x60(void*) -> PEB Linear Address
		// PEB:LoaderData(void*)                                    @ offset 0x18 (x64)
		// PEB_LDR_DATA:InMemoryOrderModuleList(LIST_ENTRY)         @ offset 0x20 (x64)
		// LDR_DATA_TABLE_ENTRY:InMemoryOrderModuleList(LIST_ENTRY) @ offset 0x10 (x64)
		// LDR_DATA_TABLE_ENTRY:DllBase(void*)                      @ offset 0x30 (x64)
		// LDR_DATA_TABLE_ENTRY:BaseDllName(UNICODE_STRING)         @ offset 0x58 (x64)
		LIST_ENTRY* GetModuleList() {
			void* PEB = (void*)__readgsqword(0x60);       // Get PEB
			void* LoaderData = (void*)((ptr)PEB + 0x18);  // Get PEB:LoaderDara
			LoaderData = *(void**)LoaderData;             // Get Linear Address of LoaderData

			return (LIST_ENTRY*)((ptr)LoaderData + 0x20); // Get List
		}
		HMODULE GetModuleHandleThroughPeb(
			_In_ const wchar* ModuleName
		) {
			LIST_ENTRY* InMemoryOrderModuleList = GetModuleList();
			LIST_ENTRY* ListIterator = InMemoryOrderModuleList;
			while (ListIterator->Flink != InMemoryOrderModuleList) {
				ListIterator = ListIterator->Flink;

				UNICODE_STRING* DllName = (UNICODE_STRING*)((ptr)ListIterator + 0x48); // Get DllBaseName
				size_t ModuleNameSize = nrt::wcslen(ModuleName) * sizeof(*ModuleName);
				if (DllName->Length == ModuleNameSize)
					if (RtlCompareMemory(DllName->Buffer, ModuleName, ModuleNameSize) == ModuleNameSize)
						return *(HMODULE*)((ptr)ListIterator + 0x20); // Get DllBaseAddress
			}

			return nullptr;
		}
		HMODULE GetModuleHandleByHash(
			_In_ fnv Hash
		) {
			LIST_ENTRY* InMemoryOrderModuleList = GetModuleList();
			LIST_ENTRY* ListIterator = InMemoryOrderModuleList;
			while (ListIterator->Flink != InMemoryOrderModuleList) {
				ListIterator = ListIterator->Flink;

				UNICODE_STRING* DllName = (UNICODE_STRING*)((ptr)ListIterator + 0x48); // Get DllBaseName
				if (FNV1aHash(DllName->Buffer, DllName->Length) == Hash)
					return *(HMODULE*)((ptr)ListIterator + 0x20); // Get DllBaseAddress
			}

			return nullptr;
		}

		void* ImportFunctionByHash(
			_In_ const HMODULE hMod,
			_In_ const fnv     Hash
		) {
			auto NtHeader = GetNtHeader(hMod);
			if (!NtHeader)
				return nullptr;

			auto ModuleBase = (ptr)hMod;
			auto ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)
				((ptr)NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ModuleBase);
			auto ppNameTable = (dword*)((ptr)ExportDirectory->AddressOfNames + ModuleBase);

			for (u32 i = 0; i < ExportDirectory->NumberOfNames; i++) {
				auto sz = (const char*)((ptr)ppNameTable[i] + ModuleBase);
				auto IHash = FNV1aHash((void*)sz, nrt::strlen(sz));

				if (IHash == Hash) {
					auto OrdinalTable = (word*)((ptr)ExportDirectory->AddressOfNameOrdinals + ModuleBase);
					auto FunctionTable = (dword*)((ptr)ExportDirectory->AddressOfFunctions + ModuleBase);
					return (void*)((ptr)FunctionTable[OrdinalTable[i]] + ModuleBase);
				}
			}

			return nullptr; // No matching import found
		}
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
