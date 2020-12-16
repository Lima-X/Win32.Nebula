// Packed-Crypto-Engine
#include "shared.h"

namespace cry {
	class XPress {
		typedef unsigned long NTSTATUS;
		typedef NTSTATUS(NTAPI* rtlccom_t)(
			_In_                                                              USHORT CompressionFormatAndEngine,
			_In_reads_bytes_(UncompressedBufferSize)                          PUCHAR UncompressedBuffer,
			_In_                                                              ULONG  UncompressedBufferSize,
			_Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
			_In_                                                              ULONG  CompressedBufferSize,
			_In_                                                              ULONG  UncompressedChunkSize,
			_Out_                                                             PULONG FinalCompressedSize,
			_In_                                                              PVOID  WorkSpace
			);
		typedef NTSTATUS(NTAPI* rtldcom_t)(
			_In_                                                                  USHORT CompressionFormat,
			_Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
			_In_                                                                  ULONG  UncompressedBufferSize,
			_In_reads_bytes_(CompressedBufferSize)                                PUCHAR CompressedBuffer,
			_In_                                                                  ULONG  CompressedBufferSize,
			_Out_                                                                 PULONG FinalUncompressedSize,
			_In_opt_                                                              PVOID  WorkSpace
			);
		typedef NTSTATUS(NTAPI* rtlgwss_t)(
			_In_  USHORT CompressionFormatAndEngine,
			_Out_ PULONG CompressBufferWorkSpaceSize,
			_Out_ PULONG CompressFragmentWorkSpaceSize
			);
		static constexpr USHORT COMPRESSOR_MODE = 0x0104;
		static constexpr USHORT COMPRESSOR_CHUCK = 0x1000;

	public:
		XPress()
			: m_NtDll(GetModuleHandleW(L"ntdll.dll")) {
			u32 v0;
			RtlGetCompressionWorkSpaceSize(COMPRESSOR_MODE, (ULONG*)&m_WorkSpaceSize, (ULONG*)&v0);
			m_WorkSpace = VirtualAlloc(nullptr, m_WorkSpaceSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}
		~XPress() {
			VirtualFree(m_WorkSpace, 0, MEM_RELEASE);
		}

		status CompressBufferInplace(
			_In_ void* Buffer,
			_In_ size_t Size
		) {

		}

		status DecompressBufferInplace(
			_In_ void* Buffer,
			_In_ size_t Size
		) {

		}

	private:
		HMODULE   m_NtDll;
		void*     m_WorkSpace;
		u32       m_WorkSpaceSize;
		rtlccom_t RtlCompressBuffer              = (rtlccom_t)GetProcAddress(m_NtDll, "RtlCompressBuffer");
		rtldcom_t RtlDecompressBufferEx          = (rtldcom_t)GetProcAddress(m_NtDll, "RtlDecompressBufferEx");
		rtlgwss_t RtlGetCompressionWorkSpaceSize = (rtlgwss_t)GetProcAddress(m_NtDll, "RtlGetCompressionWorkSpaceSize");
	};
}
