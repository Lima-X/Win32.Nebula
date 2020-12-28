// No Runtime Library: Provides subroutines for the compiler/dev that emulate the CRT
#pragma once
// Link against ntdll (Full link through private lib)
#pragma comment(lib, "ntdllp.lib")

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef struct _UNICODE_STRING {
	                                                   USHORT Length;
	                                                   USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#ifdef __cplusplus
extern "C" {
#else
{
#endif
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

	IMPORT int __cdecl swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);
	IMPORT int __cdecl vswprintf_s(wchar_t* buffer, size_t numberOfElements, const wchar_t* format, va_list argptr);
	IMPORT int __cdecl vsprintf_s(char* buffer, size_t numberOfElements, const char* format, va_list argptr);
	// IMPORT wchar_t* __cdecl wcschr(const wchar_t* str, wchar_t c);
}
#pragma endregion
