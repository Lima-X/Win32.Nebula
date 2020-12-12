/* This File is shared between the core Projects and provides intercompatibility between them. */
#pragma once

#include "sub/sub.h"

namespace utl {
	namespace img {
		IMAGE_NT_HEADERS*     GetNtHeader(_In_ HMODULE hMod);
		IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const byte Name[8]);
	}
}