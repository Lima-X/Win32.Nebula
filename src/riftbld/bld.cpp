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

	status GetExportImageAddress(
		_In_  handle      Module,
		_In_  const char* ExportName,
		_Out_ void*&      ExportAddress
	) {
		auto NtHeader = utl::GetNtHeader(Module);
		auto ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((ptr)img::TranslateRvaToPa(Module,
			NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (ptr)Module);
		Con->PrintFEx(CON_INFO, L"ExportDirectory at 0x%08x", (ptr)ExportDirectory - (ptr)Module);

		u16 Ordinal = -1; // Set to invalid ordinal by default

		if (*ExportName != '@') { // Find ordinal of export
			// Enumerate ExportNameTable and find matching entry
			auto ExportNameTable = (u32*)((ptr)img::TranslateRvaToPa(Module, ExportDirectory->AddressOfNames) + (ptr)Module);
			Con->PrintFEx(CON_INFO, L"ExportNameTable at 0x%08x", (ptr)ExportNameTable - (ptr)Module);

			// Find exportname
			for (auto i = 0; i < ExportDirectory->NumberOfNames; i++) {
				auto ExportedName = (char*)((ptr)img::TranslateRvaToPa(Module, ExportNameTable[i]) + (ptr)Module);

				if (!strcmp(ExportedName, ExportName)) {
					Con->PrintFEx(CON_INFO, L"Exported name found at 0x%08x", (ptr)ExportedName - (ptr)Module);
					auto ExportOrdinalTable = (u16*)((ptr)img::TranslateRvaToPa(
						Module, ExportDirectory->AddressOfNameOrdinals) + (ptr)Module);
					Con->PrintFEx(CON_INFO, L"ExportOrdinalTable at 0x%08x", (ptr)ExportOrdinalTable - (ptr)Module);

					Ordinal = ExportOrdinalTable[i]; break;
				}
			}
		} else // directly use ordinal
			Ordinal = atoi(ExportName + 1);

		if (Ordinal != (u16)-1) {
			if (Ordinal > ExportDirectory->NumberOfFunctions) {
				Con->PrintFEx(CON_ERROR, L"Ordinal outside of ExportAddressTable: @%d", Ordinal);
				return S_CREATE(SS_ERROR, SF_BUILDER, SC_INVALID_PARAMETER);
			}

			// Remove export rva from eat
			auto ExportAddressTable = (u32*)((ptr)img::TranslateRvaToPa(Module,
				ExportDirectory->AddressOfFunctions) + (ptr)Module);
			Con->PrintFEx(CON_INFO, L"ExportAddressTable at 0x%08x", (ptr)ExportAddressTable - (ptr)Module);

			ExportAddress = (void*)((ptr)img::TranslateRvaToPa(Module, ExportAddressTable[Ordinal]) + (ptr)Module);
			Con->PrintFEx(CON_SUCCESS, L"Removed Export @%d, at 0x%08x", Ordinal, (ptr)(ExportAddress) - (ptr)Module);
		} else {
			Con->PrintFEx(CON_WARNING, L"Export not found");
			return S_CREATE(SS_WARNING, SF_BUILDER, SC_INVALID_POINTER);
		}

		return SUCCESS;
	}
}