/* Special Header for .ldr (Main Code) */
// The .ldr is seperated from the normal Binary that actually contains the actual code
#pragma once

// Merge const and nonconst data into one section
#ifndef _DEBUG
#pragma comment(linker, "/merge:.ldrd=.ldr")
#endif

#include "sub/sub.h"
#include "nrt/nrt.h"

/* This Block has to enclose all code & data that belongs to the loaderstub

	#ifdef N_LDR
	#pragma  code_seg(".ldr")
	#pragma  data_seg(".ldrd")
	#pragma const_seg(".ldrd")
	#endif
		... <- Code here

	#ifdef N_LDR
	#pragma const_seg()
	#pragma  data_seg()
	#pragma  code_seg()
	#endif
*/

/* Everything that belongs to the loaderstub is stored within the ".ldr"-Section,
   the loaderstub has no access to anything outside of ".ldr"-Section. */

namespace ldr {

}

namespace utl {
	typedef unsigned long long fnv;

	namespace img {
		IMAGE_NT_HEADERS*     GetNtHeader(_In_ HMODULE hMod);
		IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const byte Name[8]);
		void*                 ImportFunctionByHash(_In_ const HMODULE hMod, _In_ const utl::fnv Hash);
	}

	fnv FNV1aHash(_In_ void* Data, _In_ size_t Size);
}

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}