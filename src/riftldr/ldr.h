#pragma once

// Merge const and nonconst data into one section
#ifndef _DEBUG
#pragma comment(linker, "/merge:.rdata=.data")
#endif

#include "shared.h"

#pragma region Protected Sections
// Ldr Sections
#pragma section(".nbr", read)       // Constsection
#pragma section(".nbw", write)      // Datasection
// #pragma section(".nbx", execute) // Text/Code -Section

// Merge ldr sections
#ifndef _DEBUG
#pragma warning(disable : 4330)
// #pragma comment(linker, "/ignore:4254") // Doesnt work in a pragma because WHO KNOWS WHY, so i set it in the Commandline.. smh

// Merge protected sections
#pragma section(".nb", read, write, execute)
#pragma comment(linker, "/merge:.nbr=.nb")
#pragma comment(linker, "/merge:.nbw=.nb")
#pragma comment(linker, "/merge:.nbx=.nb")

// Merge loader code into a loader section
#pragma section(".ldr", read, write, execute)
#pragma comment(linker, "/merge:.text=.ldr")
#pragma comment(linker, "/merge:.data=.ldr")
#pragma comment(linker, "/merge:.rdata=.ldr")

#endif
#define N_PROTECTEDR ALLOC_DATA(".nbr")
#define N_PROTECTEDW ALLOC_DATA(".nbw")
#define N_PROTECTEDX ALLOC_CODE(".nbx")
#pragma endregion

namespace ldr {

}

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}
