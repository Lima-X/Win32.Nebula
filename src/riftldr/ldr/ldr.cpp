#include "..\ldr.h"

namespace ldr {
	EXTERN_C EXPORT const dword TlsLoaderConfiguation = 0;

	/* Thread-Local-Storage (TLS) Callback :
	   This will start the Protection-Services,
	   decrypt and unpack the actuall code
	   and ensure code integrity. */
	// static bool l_bTlsFlag = false;
	void __stdcall TlsCoreLoader(
		_In_ void* DllHandle,
		_In_ u32   dwReason,
		_In_ void* Reserved
	) {
		UNREFERENCED_PARAMETER(DllHandle);
		UNREFERENCED_PARAMETER(Reserved);

		switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			{
			#ifdef _DEBUG
				ptr BaseAddress = (ptr)GetModuleHandleW(nullptr);
				IMAGE_NT_HEADERS* NtHeader = utl::img::GetNtHeader((HMODULE)BaseAddress);

				// This will unprotect all memory of the section and allow full access to it,
				// its only valid for Debug-Configuration, on Release this has to be done through the builder
				// byte LoaderSegName[8] = ".ldrx";
				// IMAGE_SECTION_HEADER* LoaderSection = utl::img::FindSection(NtHeader, LoaderSegName);
				dword OldProtection;
				// VirtualProtect((void*)((ptr)LoaderSection->VirtualAddress + BaseAddress), LoaderSection->Misc.VirtualSize,
				//	PAGE_EXECUTE_READWRITE, &OldProtection);

				// Simulate Inaccessable .text, .data and .rdata Sections by setting Pageprotections to NoAccess
				byte NoAccessSections[4][8] = {
					".ldr",
					".ldrr",
					".ldrw",
					".ldrx"
				};
				IMAGE_SECTION_HEADER* SectionPointers[4];
				dword OldSectionProtections[4];
				for (u8 i = 0; i < 4; i++) {
					SectionPointers[i] = utl::img::FindSection(NtHeader, NoAccessSections[i]);
					if (SectionPointers[i])
						VirtualProtect((void*)((ptr)SectionPointers[i]->VirtualAddress + BaseAddress), SectionPointers[i]->Misc.VirtualSize,
							PAGE_NOACCESS, OldSectionProtections + i);
				}
			#endif
				// l_bTlsFlag = true;

				auto a = utl::FNV1aHash((void*)"LdrLoadDll", 10);

				auto nt = utl::img::GetModuleHandleByHash(N_NTDLL);
				auto func = utl::img::ImportFunctionByHash(nt, a);

				auto k32 = utl::img::GetModuleHandleByHash(N_KRNL32);

				// cry::XPressH compressor;

				// Initialize

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

				   3. Decrypt & unpack the core (per registered section):
					  - Undo Base-Relocations in region (fix corrupted data)
					  - Decrypt (aes256cbc-bcrypt)
					  - Unpack (LZ77+Huffman (RtlCompressBuffer))
					  - Reapply Base-Relocations on section
					  - Ensure integrity of unpacked code/data (hashing (sha256 per section))
				*/

			#ifdef _DEBUG
				// Revert Pageprotections on Blocked Sections (this simulates a Successful decryption)
				for (u8 i = 0; i < 4; i++)
					if (SectionPointers[i]) {
						ptr address = ((ptr)SectionPointers[i]->VirtualAddress + BaseAddress);
						size_t size = SectionPointers[i]->Misc.VirtualSize;

						VirtualProtect((void*)address, size, OldSectionProtections[i], &OldProtection);

						// VirtualProtect((void*)((ptr)SectionPointers[i]->VirtualAddress + BaseAddress), SectionPointers[i]->Misc.VirtualSize,
						//	OldSectionProtections[i], &OldProtection);
					}
			#endif
			} break;
		case DLL_PROCESS_DETACH:
			;
		}
	}
}

/* This is porbably the worst workaround ever in this whole project (including the old one).
   But this wasnt even my choice, Microsoft's Linker has forced my hands
   and only because this shitty linker lacks some serious basic functionality in some corners
   like not being able to just properly handly section merge requests and giving you a useless
   LNK4254 warning or just directly refusing to put the code into the section you specified...

   @Microsoft: If you ever read this (which i doubt) FIX YOUR FUCKING LINKER,
               CAUSE RANDOMLY GETTING LNK1000 INTERNAL ERROR FUCKING SUCKS !                */
extern "C" {
	u32 _tls_index = 0;
	const PIMAGE_TLS_CALLBACK _tls_callback[] = {
		(PIMAGE_TLS_CALLBACK)ldr::TlsCoreLoader,
		(PIMAGE_TLS_CALLBACK)nullptr
	};

	#pragma comment (linker, "/include:_tls_used")
	extern const IMAGE_TLS_DIRECTORY64 _tls_used = {
		(ptr)0, (ptr)0,      // tls data (unused)
		(ptr)&_tls_index,    // address of tls_index
		(ptr)&_tls_callback, // pointer to call back array
		(u32)0, (u32)0       // tls properties
	};
}
