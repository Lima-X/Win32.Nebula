#pragma once

// Merge const and nonconst data into one section
#ifndef _DEBUG
#pragma comment(linker, "/merge:.rdata=.data")
#endif

#include "shared.h"

// Ldr Sections
#pragma section(".ldrr", read)       // Constsection
#pragma section(".ldrw", write)      // Datasection
// #pragma section(".ldrx", execute) // Text/Code -Section

// Merge ldr sections
#ifndef _DEBUG
#pragma warning(disable : 4330)
#pragma section(".ldr", read, write, execute)
// #pragma comment(linker, "/ignore:4254") // Doesnt work in a pragma because WHO KNOWS WHY, so i set it in the Commandline.. smh
#pragma comment(linker, "/merge:.ldrr=.ldr")
#pragma comment(linker, "/merge:.ldrw=.ldr")
#pragma comment(linker, "/merge:.ldrx=.ldr")
#endif
#define N_PROTECTEDR ALLOC_DATA(".ldrr")
#define N_PROTECTEDW ALLOC_DATA(".ldrw")
#define N_PROTECTEDX ALLOC_CODE(".ldrx")

#pragma region Loader FNV-1a Hashes
#define N_NTDLL 0xfd96b5caa3a9c6d9 // L"ntdll.dll"


#define N_KRNL32 0x7f1bf8b449d16c2d // L"kernel32.dll"

#pragma endregion


namespace ldr {

}

namespace svc {
	poly ServiceCall(_In_range_(0, 0xffff) u32 svcId, _In_opt_ ...);
	poly ServiceDispatch(_In_range_(0, 0xffff) u32 svcId, _In_opt_ va_list val);
}
