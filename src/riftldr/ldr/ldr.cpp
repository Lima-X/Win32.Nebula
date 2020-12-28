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
				auto BaseAddress = (handle)GetModuleHandleW(nullptr);
				auto* NtHeader = utl::GetNtHeader(BaseAddress);
				const char ProtectedSections[4][8] = { ".nb", ".nbr", ".nbw", ".nbx" };
			#ifdef _DEBUG
				// Simulate Inaccessable protected Sections by setting Pageprotections to NoAccess
				IMAGE_SECTION_HEADER* SectionPointers[4];
				dword OldSectionProtections[4];
				for (u8 i = 0; i < 4; i++) {
					SectionPointers[i] = utl::FindSection(NtHeader, ProtectedSections[i]);
					if (SectionPointers[i])
						VirtualProtect((void*)((ptr)SectionPointers[i]->VirtualAddress + (ptr)BaseAddress), SectionPointers[i]->Misc.VirtualSize,
							PAGE_NOACCESS, OldSectionProtections + i);
				}
			#endif
				// l_bTlsFlag = true;





				// cry::XPressH compressor;

				// Initialize

				/* Execution Plan:
				   1. Protect TLS (Stage-1):
					  - Hide Thread
					  - Basic debugger tests
					  - Check Systemcalls

				   2. Ensure integrity of the loaderstub (selfhashing (sha256-bcrypt))

				   3. Start Protection-Services (Protect TLS Stage-2):
					  - MemoryScanner
					  - Test for Virtual Environment
					  - Run all Debugger Checks

				   4. Decrypt & unpack the core (per registered section):
					  - Undo Base-Relocations in region (fix corrupted data)
					  - Decrypt (aes256cbc-bcrypt)
					  - Unpack (LZ77+Huffman (RtlCompressBuffer))
					  - Reapply Base-Relocations on section
					  - Ensure integrity of unpacked code/data (hashing (sha256 per section))
				*/

			// Stage 4:
				// Load bcrypt.dll
				wchar SystemDirectory[MAX_PATH];
				GetSystemDirectoryW(SystemDirectory, MAX_PATH);
				wchar BCryptDll[MAX_PATH];
				utl::GetSystemDllbyHash(SystemDirectory, N_BCRYPTDLL, BCryptDll);
				handle BCry = LoadLibraryW(BCryptDll);
				auto BCryptOpenAlgorithmProvider = (cry::bcryoap_t)utl::ImportFunctionByHash(BCry, N_BCOALGPRO);

				i64 BaseDelta = (i64)BaseAddress - 0x140000000;
				for (u8 i = 0; i < 4; i++) {
					auto Section = utl::FindSection(NtHeader, ProtectedSections[i]);
					if (!Section)
						continue;

					// Reverse Relocs (reverse damage done by Ldr to the protected sections)
					void* SectionAddress = (void*)((ptr)Section->VirtualAddress + (ptr)BaseAddress);
					dword OldProtection;
					VirtualProtect(SectionAddress, Section->Misc.VirtualSize, PAGE_READWRITE, &OldProtection);
					status SLdr = utl::ApplyBaseRelocationsOnSection(BaseAddress, Section, nullptr, -BaseDelta);
					if(S_ERROR(SLdr))
					VirtualProtect(SectionAddress, Section->Misc.VirtualSize, PAGE_READWRITE, &OldProtection);

					// Decrypt Aes256Cbc
					BCRYPT_ALG_HANDLE AesAlg;

					BCryptOpenAlgorithmProvider(&AesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0); // Obfuscate "AES" (BCRYPT_AES_ALGORITHM)
					// BCryptImportKey()


					// Uncompress LZ77+Huffman



					// Reapply BaseRelocations
					utl::ApplyBaseRelocationsOnSection(BaseAddress, Section, nullptr, BaseDelta);
				}

			#ifdef _DEBUG
				// Revert Pageprotections on Blocked Sections (this simulates a Successful decryption)
				for (u8 i = 0; i < 4; i++)
					if (SectionPointers[i]) {
						ptr address = ((ptr)SectionPointers[i]->VirtualAddress + (ptr)BaseAddress);
						size_t size = SectionPointers[i]->Misc.VirtualSize;

						dword OldProtection;
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
