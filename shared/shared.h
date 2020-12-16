// This File is shared between the core Projects and provides intercompatibility between them.
#pragma once

#include "sub/sub.h"
#include "nrt/nrt.h"

namespace utl {
	typedef unsigned long long fnv;

	namespace img {
		IMAGE_NT_HEADERS*     GetNtHeader(_In_ HMODULE hMod);
		IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const byte Name[8]);
		void*                 ImportFunctionByHash(_In_ const HMODULE hMod, _In_ const fnv Hash);
		HMODULE               GetModuleHandleThroughPeb(_In_ const wchar* ModuleName);
		HMODULE               GetModuleHandleByHash(_In_ fnv Hash);
	}

	constexpr fnv FNV1aHash(_In_ void* Data, _In_ size_t Size);
}
