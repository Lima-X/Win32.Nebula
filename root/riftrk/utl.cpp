#include "riftrk.h"

namespace ncrt {
	inline size_t memcmp(
		_In_ const void*  mem1,
		_In_ const void*  mem2,
		_In_       size_t nmem
	) {
		const byte* v1 = (byte*)mem1, * v2 = (byte*)mem2;
		while (*v1++ == *v2++ && --nmem);
		return nmem;
	}

	inline size_t strlen(
		_In_z_ const char* sz
	) {
		size_t n = 0;
		while (*sz++)
			n++;
		return n;
	}
}

namespace img {
	IMAGE_NT_HEADERS* GetNtHeader(
		_In_ HMODULE hMod
	) {
		IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)hMod + ((IMAGE_DOS_HEADER*)hMod)->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr; // Invalid Signature
		if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return nullptr; // Invalid Signature

		return NtHeader;
	}

	constexpr void* GetDataDirectory(
		_In_ IMAGE_NT_HEADERS* NtHeader,
		_In_ uint8             Directory
	) {
		return (void*)(NtHeader->OptionalHeader.DataDirectory[Directory].VirtualAddress
			+ NtHeader->OptionalHeader.ImageBase);
	}
}


// EAT Hooks arent really doable in 64bit mode as the rva table only has 32bit members
// and GetProcAddress adds the ImageBase onto it
status InstallEATHook(
	_In_       HMODULE hMod,
	_In_ const char*   szName,
	_In_ const void*   fnHook
) {
	IMAGE_NT_HEADERS* NtHeader = img::GetNtHeader(hMod);
	if (!NtHeader)
		return -1;
	IMAGE_EXPORT_DIRECTORY* ExportDirectory =
		(IMAGE_EXPORT_DIRECTORY*)img::GetDataDirectory(NtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);

	ptr ImageBase = NtHeader->OptionalHeader.ImageBase;
	const void* NameRVATable = (const char**)((ptr)ExportDirectory->AddressOfNames + ImageBase);
	size_t nName = ncrt::strlen(szName) + 1;
	for (uint16 i = 0; i < ExportDirectory->NumberOfNames; i++) {
		const char* Name = (char*)((ptr)*((dword*)NameRVATable + i) + ImageBase);

		if (!ncrt::memcmp(Name, szName, nName)) {
			uint16 Ordinal = ((uint16*)(ExportDirectory->AddressOfNameOrdinals + ImageBase))[i];
			void** FunctionTable = (void**)(ExportDirectory->AddressOfFunctions + ImageBase);
			void* FunctionEntry = (void*)(FunctionTable + Ordinal);

			dword OldProtection;
			VirtualProtect(FunctionEntry, sizeof(void*), PAGE_READWRITE, &OldProtection);
			_InterlockedExchange((long*)FunctionEntry, (ptr)fnHook - ImageBase);
			VirtualProtect(FunctionEntry, sizeof(void*), OldProtection, &OldProtection);

			return i;
		}
	}

	return -3; // Export Not Found
}

status InstallIATHook(
	_In_       HMODULE hMod,
	_In_ const char*   szName,
	_In_ const void*   fnHook
) {
	IMAGE_NT_HEADERS* NtHeader = img::GetNtHeader(hMod);
	if (!NtHeader)
		return -1;
	IMAGE_IMPORT_DESCRIPTOR* ImportDirectory =
		(IMAGE_IMPORT_DESCRIPTOR*)img::GetDataDirectory(NtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	ptr ImageBase = NtHeader->OptionalHeader.ImageBase;
	ptr* ImportLookupTable = (ptr*)(ImportDirectory->Characteristics + ImageBase);
	size_t nName = ncrt::strlen(szName) + 1;
	void** ImportAddressTable = (void**)(ImportDirectory->FirstThunk + ImageBase);
	for (int i = 0; ImportLookupTable[i]; i++)
	#ifdef _M_X64
		if (!(ImportLookupTable[i] & (ptr)1 << 63)) {
	#elif _M_IX86
		if (!(ImportLookupTable[i] & 1 << 31)) {
	#endif
			const char* Name = (char*)(ImportLookupTable[i] + ImageBase + 2);
			if (!ncrt::memcmp(Name, szName, nName)) {
				void** FunctionThunk = ImportAddressTable + i;

				dword OldProtection;
				VirtualProtect(FunctionThunk, sizeof(void*), PAGE_READWRITE, &OldProtection);
			#ifdef _M_X64
				_InterlockedExchange64((long long*)FunctionThunk, (long long)fnHook);
			#elif _M_IX86
				_InterlockedExchange((long*)FunctionThunk, (long)fnHook);
			#endif
				VirtualProtect(FunctionThunk, sizeof(void*), OldProtection, &OldProtection);

				return i;
			}
		}

	return -3; // Export Not Found
}