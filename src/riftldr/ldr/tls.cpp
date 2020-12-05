#include "..\ldr.h"

#pragma code_seg(".ldr")
#pragma const_seg(".ldrc")
#pragma data_seg(".ldrd")
namespace ldr {
	namespace utl {
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

		IMAGE_SECTION_HEADER* FindSection(
			_In_ IMAGE_NT_HEADERS* NtHeader,
			_In_ const byte        Name[8]
		) {
			// Iterate over Sections
			IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
			for (u8 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
				if (RtlCompareMemory(SectionHeader->Name, Name, 8) == 8)
					return SectionHeader;

				SectionHeader++;
			}
		}
	}


	/* Thread Local Storage (TLS) Callback :
	   This will start the Protection Services
	   and partially initialize _riftldr       */
	static bool l_bTlsFlag = false;
	void NTAPI TlsCallback(
		_In_ PVOID DllHandle,
		_In_ DWORD dwReason,
		_In_ PVOID Reserved
	) {
		UNREFERENCED_PARAMETER(DllHandle);
		UNREFERENCED_PARAMETER(dwReason);
		UNREFERENCED_PARAMETER(Reserved);
		if (!l_bTlsFlag) {
		#ifdef _DEBUG
			{	// Will
				ptr BaseAddress = (ptr)GetModuleHandleW(nullptr);
				IMAGE_NT_HEADERS* NtHeader = utl::GetNtHeader((HMODULE)BaseAddress);
				byte LoaderSegName[8] = ".ldr";
				IMAGE_SECTION_HEADER* LoaderSection = utl::FindSection(NtHeader, LoaderSegName);
				dword OldProtection;
				VirtualProtect((void*)((ptr)LoaderSection->VirtualAddress + BaseAddress), LoaderSection->Misc.VirtualSize,
					PAGE_EXECUTE_READWRITE, &OldProtection);
			}
		#endif
			l_bTlsFlag = true;

			MessageBoxW(0, L"DLL_THREAD_ATTACH", L"DLL_THREAD_ATTACH", 0);

			// TracePoint("Executing TLS Callback: " __FUNCTION__);
			// VirtualProtect()

			// img::IHashBinaryCheck();
			// cry::Hash::hash sha;
			// img::HashMappedSection(sha);
			// bool b = memcmp(&sha, &dat::hMemoryHash, sizeof(cry::Hash::hash));

			// void* a = ImportFunctionByHash(GetModuleHandleW(L"ntdll.dll"), *(hash*)"\x4b\xef\x63\xe1\x6e\x12\x8a\xd7\x75\x1a\x37\xda\x73\x9f\x19\x88");
			// void* b = (void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrCaptureTimeout");
			// Call Anit RE Methods here...
			// (Anti Debugger, Section Hashing, Function Hooking)

			MessageBox(0, L"DLL_THREAD_ATTACH", L"DLL_THREAD_ATTACH", 0);
		}
	}

}
#pragma data_seg()
#pragma const_seg()
#pragma code_seg()

#pragma comment (linker, "/include:_tls_used")
#pragma comment (linker, "/include:TlsEntry0")
#pragma const_seg(".CRT$XLF")
extern "C" const PIMAGE_TLS_CALLBACK TlsEntry0 = ldr::TlsCallback;
#pragma const_seg()
