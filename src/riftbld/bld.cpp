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

}