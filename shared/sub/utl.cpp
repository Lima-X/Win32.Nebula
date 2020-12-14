#include "shared.h"

#ifdef N_LDR
#pragma  code_seg(".ldr")
#pragma  data_seg(".ldrd")
#pragma const_seg(".ldrd")
#endif
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
				if (RtlCompareMemory(SectionHeader->Name, Name, 8) == 8)
					return SectionHeader;

				SectionHeader++;
			}

			return nullptr;
		}

		void* ImportFunctionByHash(
			_In_ const HMODULE hMod,
			_In_ const fnv     Hash
		) {
			auto* NtHeader = GetNtHeader(hMod);
			if (!NtHeader)
				return nullptr;

			auto ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)
				(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ptr)hMod);
			auto ppNameTable = (const char**)(ExportDirectory->AddressOfNames + (ptr)hMod);

			for (u32 i = 0; i < ExportDirectory->NumberOfNames; i++) {
				const char* sz = (const char*)((ptr)ppNameTable[i] + (ptr)hMod);
				auto IHash = FNV1aHash((void*)sz, nrt::strlen(sz));

				if (IHash == Hash) // <- I could just return GetProcAddress here, but the work to do it manually from here is minimal
					return (void*)(((size_t*)(ExportDirectory->AddressOfFunctions + (ptr)hMod))
						[((word*)(ExportDirectory->AddressOfNameOrdinals + (ptr)hMod))[i]] + (ptr)hMod);
			}

			return nullptr; // Not matching import found
		}
	}

	fnv FNV1aHash(        // Genrates a 64-Bit wide FNV-1a Hash
		_In_ void*  Data, // Pointer to Data to hash
		_In_ size_t Size  // Size of Data to hash in bytes
	) {
		fnv Hash = 0xcbf29ce484222325;
		while (Size--)
			Hash = (Hash ^ *((BYTE*&)Data)++) * 0x00000100000001B3;
		return Hash;
	}

}
#ifdef N_LDR
#pragma const_seg()
#pragma  data_seg()
#pragma  code_seg()
#endif
