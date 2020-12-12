/* Special Header for .ldr (Packing-Engine) */
// The .ldr is seperated from the normal Binary that actually contains the rest of the code
#pragma once

#include "sub/sub.h"
#include "nrt/nrt.h"

// Linker->Commandline->Additional: "/MERGE:.ldrd=.ldr /MERGE:.ldrc=.ldr"
#pragma comment(linker, "/merge:.ldrd=.ldr")
#pragma comment(linker, "/merge:.ldrc=.ldr")

/* This Block has to enclose all code & data that belongs to the loaderstub

	#pragma code_seg(".ldr")
	#pragma data_seg(".ldrd")
	#pragma const_seg(".ldrc")
	namespace ldr {
		... <- Code here
	}
	#pragma const_seg()
	#pragma data_seg()
	#pragma code_seg()
*/

/* Everything that belongs to the loaderstub is stored within the ".ldr"-Section,
   the loaderstub has no access to anything outside of ".ldr"-Section. */

namespace ldr {
	namespace utl {
		IMAGE_NT_HEADERS*     GetNtHeader(_In_ HMODULE hMod);
		IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const byte Name[8]);
	}
}