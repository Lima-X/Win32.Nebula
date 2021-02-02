// Contains Code used exclusively by the Imagerecompiler to patch the binary and relink it correctly
#include "bld.h"

namespace img {
	status MovePhysicalSection(              // Moves the specified section to a new location
		_In_ IMAGE_NT_HEADERS*     NtHeader, // A pointer to the NtHeader that has to be relinked
		_In_ IMAGE_SECTION_HEADER* Section,  // The section to be moved
		_In_ ptr                   Offset    // The new offset at which the section should be moved too (Fileoffset)
	) {

		return SUCCESS;
	}

	status ResizePhysicalSection(            // Resizes the specified section and relinks the image
		_In_ IMAGE_NT_HEADERS*     NtHeader, // A pointer to the NtHeader that has to be patched
		_In_ IMAGE_SECTION_HEADER* Section,  // The Section to be resized
		_In_ size_t                NewSize   // The Size the section should be resized to
	) {
		/* Tasks:
		   1. Modifiy the sizeattributes of the section
		   2. Move and relink sections:
		      -> Find all sections after the resized section
			  -> Find bounds of the of those sections
			  -> move sections to the new location offset as a whole chunk using VIB (Virtual Intermediate Buffer)
			3. Fixup sectionheaders
			4. Fix NtHeader (ImageSize, ...) */

		return SUCCESS;
	}

	u32 TranslateRvaToPa(   // Translates a RVA to a PA in the image
		_In_ handle Module, // The module used for the translation
		_In_ u32    Rva     // The address to be translated
	) {
		auto NtHeader = utl::GetNtHeader(Module);

		// Check if rva is within headers
		if (Rva <= NtHeader->OptionalHeader.SizeOfHeaders)
			return Rva;

		// Check if rva is within sections and translate
		auto Section = IMAGE_FIRST_SECTION(NtHeader);
		for (auto i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
			if (Rva >= Section->VirtualAddress &&
				Rva <= Section->VirtualAddress + Section->SizeOfRawData)
				return Rva - Section->VirtualAddress + Section->PointerToRawData;

			Section++;
		}

		// not within the mapable image
		return null;
	}
}