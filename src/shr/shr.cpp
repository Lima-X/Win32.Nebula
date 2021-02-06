// Collection of shared utility functions between the Loader and Builder
#include "nbp.h"

namespace utl {
#pragma region Image
	IMAGE_NT_HEADERS* GetNtHeader(
		_In_ handle Module
	) {
		if (((IMAGE_DOS_HEADER*)Module)->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr; // Invalid signature

		IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)Module + ((IMAGE_DOS_HEADER*)Module)->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr; // Invalid signature
		if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return nullptr; // Invalid signature

		return NtHeader;
	}

	IMAGE_SECTION_HEADER* FindSection(
		_In_ IMAGE_NT_HEADERS* NtHeader,
		_In_ const char        Name[8]
	) {
		// Iterate over sections
		IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (auto i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
			if (*(u64*)SectionHeader->Name == *(u64*)Name)
				return SectionHeader;

			SectionHeader++;
		}

		return nullptr;
	}
#pragma endregion

	status CreatePath(           // Creates a directory with all its intermediats
		_In_z_ const wchar* Path // The FilePath to create
	) {


		return SUCCESS;
	}
}

class XPress {
	static constexpr USHORT COMPRESSOR_MODE = 0x0104;
	static constexpr USHORT COMPRESSOR_CHUNCK = 0x1000;

public:
	XPress() {
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
	void* m_WorkSpace;
	u32   m_WorkSpaceSize;
};