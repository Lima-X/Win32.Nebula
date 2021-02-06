// Nebula-private, internal file shared between the core projects, provides intercompatibility
#pragma once

#include "..\base.h"
#include "..\dbg.h"
#include "itl.h"

#define _NB_SDK 0 // Explicitly disables active components of the SDK as we are inside the core
#include "..\sdk.h"

#pragma region Runtime Library
// No Runtime Library: Provides subroutines for the compiler/dev that emulate the CRT
#pragma comment(lib, "ntdllp.lib") // Link against ntdll (Full link through private lib)

#ifdef __cplusplus
extern "C" {
#else
{
#endif
	NTSYSAPI NTSTATUS NTAPI RtlDowncaseUnicodeString(
		_Inout_ UNICODE_STRING * DestinationString,
		_In_    UNICODE_STRING * SourceString,
		_In_    BOOLEAN         AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlCompressBuffer(
		_In_                                                              USHORT CompressionFormatAndEngine,
		_In_reads_bytes_(UncompressedBufferSize)                          PUCHAR UncompressedBuffer,
		_In_                                                              ULONG  UncompressedBufferSize,
		_Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
		_In_                                                              ULONG  CompressedBufferSize,
		_In_                                                              ULONG  UncompressedChunkSize,
		_Out_                                                             PULONG FinalCompressedSize,
		_In_                                                              PVOID  WorkSpace
	);
	NTSYSAPI NTSTATUS NTAPI RtlDecompressBufferEx(
		_In_                                                                  USHORT CompressionFormat,
		_Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
		_In_                                                                  ULONG  UncompressedBufferSize,
		_In_reads_bytes_(CompressedBufferSize)                                PUCHAR CompressedBuffer,
		_In_                                                                  ULONG  CompressedBufferSize,
		_Out_                                                                 PULONG FinalUncompressedSize,
		_In_opt_                                                              PVOID  WorkSpace
	);
	NTSYSAPI NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
		_In_  USHORT CompressionFormatAndEngine,
		_Out_ PULONG CompressBufferWorkSpaceSize,
		_Out_ PULONG CompressFragmentWorkSpaceSize
	);
	NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(
		_In_ LONG ProcessId
	);
	NTSYSAPI ULONG NTAPI RtlRandomEx(
		_Inout_ PULONG Seed
	);

	IMPORT int __cdecl swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);
	IMPORT int __cdecl vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr);
	IMPORT int __cdecl vsprintf_s(char* buffer, size_t numberOfElements, const char* format, va_list argptr);
	// IMPORT wchar_t* __cdecl wcschr(const wchar_t* str, wchar_t c);

	IMPORT int __cdecl _wtoi(_In_z_ wchar_t const* _String);
	IMPORT int __cdecl atoi(_In_z_ char const* _String);
	IMPORT long __cdecl wcstol(_In_z_ wchar_t const* _String, _Out_opt_ _Deref_post_z_ wchar_t** _EndPtr, _In_ int _Radix);
}
#pragma endregion

#ifdef __cplusplus
namespace utl {
	IMAGE_NT_HEADERS*     GetNtHeader(_In_ handle hMod);
	IMAGE_SECTION_HEADER* FindSection(_In_ IMAGE_NT_HEADERS* NtHeader, _In_ const char Name[8]);

	status                CreatePath(_In_z_ const wchar* Path);
}

#if 0
class rc4 {
public:
	~rc4();

	void ksa(_In_ void* Key, _In_range_(1, 256) size_t KeyLength);
	byte prg();

	void crypt(_In_ void* Buffer, _In_ size_t BufferSize, _Out_ void* Output);
	void rc4random(_Out_ void* Buffer, _In_ size_t BufferSize);

private:
	byte m_SBox[256];      // Key'd state
	u8   m_i = 0, m_j = 0; // SBox state
};
#endif
#endif
