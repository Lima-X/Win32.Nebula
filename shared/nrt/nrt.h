// No Runtime Library: Provides subroutines for the compiler/dev that emulate the CRT
#pragma once

#include "sub/sub.h"

// Inline Definitions / Macros
#define memset(_Dst, _Val, _Size) __stosb((byte*)_Dst, (byte*)_Val, _Size)
#define memcpy(_Dst, _Src, _Size) __movsb((byte*)_Dst, (byte*)_Src, _Size)

constexpr u32 RoundUpToMulOfPow2(u32 num, u32 mul) {
	return (num + (mul - 1)) & (0 - mul);
}

// Standard Declarations
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(_In_ EXCEPTION_RECORD* ExceptionRecord, _In_ void* EstablisherFrame, _Inout_ CONTEXT* ContextRecord, _Inout_ DISPATCHER_CONTEXT* DispatcherContext);

void* __cdecl operator new(size_t size);
void __cdecl operator delete(void* mem);

namespace nrt {
	size_t strlen(_In_z_ const char* sz);
	size_t wcslen(_In_z_ const wchar* sz);
}

#pragma region NtAPI Declarations
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT                                                  Length;
	USHORT                                                  MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#pragma comment(lib, "ntdll.lib")
extern "C" {
	NTSYSAPI VOID NTAPI	RtlInitUnicodeString(
		_Out_      UNICODE_STRING* DestinationString,
		_In_opt_z_ PCWSTR          SourceString
	);

	NTSYSAPI NTSTATUS NTAPI RtlDowncaseUnicodeString(
		_Inout_ UNICODE_STRING* DestinationString,
		_In_    UNICODE_STRING* SourceString,
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

}
#pragma endregion

