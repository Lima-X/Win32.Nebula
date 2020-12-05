#include "tls.h"

#pragma code_seg(".ldr")
#pragma data_seg(".ldrd")
#pragma const_seg(".ldrc")
namespace ldr {
	namespace utl {
		IMAGE_NT_HEADERS* GetNtHeader(
			_In_ HMODULE hMod
		) {
			IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)hMod + ((IMAGE_DOS_HEADER*)hMod)->e_lfanew);
			if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
				return nullptr; // Invalid signature
			if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
				return nullptr; // Invalid signature

			return NtHeader;
		}

		IMAGE_SECTION_HEADER* FindSection(
			_In_ IMAGE_NT_HEADERS* NtHeader,
			_In_ const byte        Name[8]
		) {
			// Iterate over sections
			IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
			for (u8 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
				if (RtlCompareMemory(SectionHeader->Name, Name, 8) == 8)
					return SectionHeader;

				SectionHeader++;
			}
		}
	}



	/* Thread-Local-Storage (TLS) Callback :
	   This will start the Protection-Services,
	   decrypt and unpack the actuall code
	   and ensure code integrity. */
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
			// This will unprotect all memory of teh section and allow full access to it,
			// its only valid for Debug-Configuration, on Release this has to be done through the builder
			ptr BaseAddress = (ptr)GetModuleHandleW(nullptr);
			IMAGE_NT_HEADERS* NtHeader = utl::GetNtHeader((HMODULE)BaseAddress);
			byte LoaderSegName[8] = ".ldr";
			IMAGE_SECTION_HEADER* LoaderSection = utl::FindSection(NtHeader, LoaderSegName);
			dword OldProtection;
			VirtualProtect((void*)((ptr)LoaderSection->VirtualAddress + BaseAddress), LoaderSection->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE, &OldProtection);
		#endif
			l_bTlsFlag = true;

			/* Execution Plan:

			   1. Protect TLS (Stage-1):
				  - Hide Thread
			      - Basic debugger tests
				  - Check Systemcalls

			   2. Ensure integrity of the loaderstub (selfhashing (sha256-bcrypt))

			   4. Start Protection-Services (Protect TLS Stage-2):
			      - MemoryScanner
				  - Test for Virtual Environment
				  - Run all Debugger Checks
				     NOTE: This has to use a custom "__C_specific_handler" as the crt one cant be used
					       it will likely just wrap RtlUnwind(Ex), maybe some extra bullshit :/

			   3. Decrypt & unpack the core (per registered section):
			      - Undo Base-Relocations in region (fix corrupted data)
				  - Decrypt (aes256cbc-bcrypt)
				  - Unpack (deflate32-internal)
				  - Reapply Base-Relocations on section
				  - Ensure integrity of unpacked code/data (hashing (sha256 per section))
			*/
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
