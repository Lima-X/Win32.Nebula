// Inline/Template Library: Defines templates, inline and constant expression functions
#pragma once

#ifdef __cplusplus
constexpr u32 RoundUpToMulOfPow2(u32 num, u32 mul) {
	return (num + (mul - 1)) & (0 - mul);
}

// NoCRT Allocators for Objects
inline void* __cdecl operator new(size_t size) {
	return HeapAlloc(GetProcessHeap(), NULL, size);
}
inline void __cdecl operator delete(void* mem) {
	HeapFree(GetProcessHeap(), NULL, mem);
}
#endif
