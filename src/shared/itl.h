// Inline/Template Library: Defines templates, inline and constant expression functions
#pragma once

#ifdef __cplusplus
// NoCRT Allocators for Objects
inline void* __cdecl operator new(size_t size) {
	return HeapAlloc(GetProcessHeap(), NULL, size);
}
inline void __cdecl operator delete(void* mem) {
	HeapFree(GetProcessHeap(), NULL, mem);
}

namespace utl {
#pragma region Fnv1a Algorithms
	constexpr u64 Fnv64OffsetBasis = 0xcbf29ce484222325;
	constexpr void Fnv1a64Hash( // Generates a 64-Bit wide FNV-1a hash
		_In_    void*  Data,    // Pointer to data to hash
		_In_    size_t Size,    // Size of data to hash in bytes
		_Inout_ u64&   Hash     // The hash to be updated

	) {
		while (Size--)
			Hash = (Hash ^ *((byte*&)Data)++) * 0x00000100000001b3;
	}
	constexpr u64 Fnv1a64Hash( // Generates a 64-Bit wide FNV-1a hash
		_In_ void*  Data,      // Pointer to data to hash
		_In_ size_t Size       // Size of data to hash in bytes
	) {
		auto Hash = Fnv64OffsetBasis;
		Fnv1a64Hash(Data, Size, Hash);
		return Hash;
	}

	// FNV1A32 ONLY IMPLEMENTED FOR COMPLETENES, ALWAYS USE 64-BIT VERSION UNLESS NECESSARY
	constexpr u32 Fnv32OffsetBasis = 0x811c9dc5;
	constexpr void Fnv1a32Hash( // Generates a 32-Bit wide FNV-1a hash
		_In_    void*  Data,    // Pointer to data to hash
		_In_    size_t Size,    // Size of data to hash in bytes
		_Inout_ u32&   Hash     // The hash to be updated

	) {
		while (Size--)
			Hash = (Hash ^ *((byte*&)Data)++) * 0x01000193;
	}
	constexpr u32 Fnv1a32Hash( // Generates a 32-Bit wide FNV-1a hash
		_In_ void*  Data,      // Pointer to data to hash
		_In_ size_t Size       // Size of data to hash in bytes
	) {
		auto Hash = Fnv32OffsetBasis;
		Fnv1a32Hash(Data, Size, Hash);
		return Hash;
	}
#pragma endregion

	constexpr u32 RoundUpToMulOfPow2(u32 num, u32 mul) {
		return (num + (mul - 1)) & (0 - mul);
	}
}
#endif
