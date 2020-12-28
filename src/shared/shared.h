// This File is shared between the core Projects and provides intercompatibility between them.
#pragma once

#include "sub/base.h"
#include "itl.h"

#include <bcrypt.h>

#ifdef __cplusplus
namespace utl {
	typedef unsigned long long fnv;
	constexpr fnv FNV1aHash(_In_ void* Data, _In_ size_t Size);

	IMAGE_NT_HEADERS*     GetNtHeader(_In_ handle hMod);
	IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const char Name[8]);
	#undef SearchPath
	status                GetSystemDllbyHash(_In_ wchar* SearchPath, _In_ fnv Hash, _Out_ wchar* Path);
	void*                 ImportFunctionByHash(_In_ handle Module, _In_ fnv Hash);
	handle                GetModuleHandleByHash(_In_ fnv Hash);
	status                ApplyBaseRelocationsOnSection(_In_ handle Module, _In_ IMAGE_SECTION_HEADER* Section, _In_opt_ void* Address, _In_ i64 RelocationDelta);

	status                CreatePath(_In_z_ const wchar* Path);
}

namespace cry {
	typedef NTSTATUS(WINAPI* bcryoap_t)(
		_Out_    BCRYPT_ALG_HANDLE* phAlgorithm,
		_In_     LPCWSTR            pszAlgId,
		_In_opt_ LPCWSTR            pszImplementation,
		_In_     ULONG              dwFlags
		);

	class BHash {
	public:
		struct sha2 {
			byte hash[32];
		} m_Hash;

		BHash(
			_In_z_ const wchar* AlgorithmId = nullptr
		);
		~BHash();
		status HashData(_In_ void* pBuffer, _In_ size_t nBuffer);
		status HashFinalize();
	private:
		volatile static u32                s_nRefCount;
		         static handle             s_BCry;
		         static BCRYPT_ALG_HANDLE  s_ah;
		         static size_t             s_nObj;
		                BCRYPT_HASH_HANDLE m_hh;
		                void*              m_pObj;
	};
}
#endif
