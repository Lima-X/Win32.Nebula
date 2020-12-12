#include "shared.h"

namespace utl {
	namespace img {
		IMAGE_NT_HEADERS* GetNtHeader(
			_In_ HMODULE hMod
		) {
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
	}
}