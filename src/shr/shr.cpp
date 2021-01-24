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
		for (u8 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
			if (*(qword*)SectionHeader->Name == *(qword*)Name)
				return SectionHeader;

			SectionHeader++;
		}

		return nullptr;
	}
#pragma endregion

#pragma region RC4Crypt
	void rc4::ksa(                          // Key-Scheduling-Algorithm (KSA)
		_In_               void* Key,       // The key used to initialize the state
		_In_range_(1, 256) size_t KeyLength // The length of the key to use in bytes
	) {
		for (auto i = 0; i < 256; i++)
			m_SBox[i] = i;
		for (auto i = 0; i < 256; i++) {
			m_j += m_SBox[i] + ((byte*)Key)[i % KeyLength];
			{ auto T = m_SBox[i]; m_SBox[i] = m_SBox[m_j]; m_SBox[m_j] = T; }
		}
		m_i = 0; m_j = 0;
	}
	byte rc4::prg() { // Updates the current state and returns the next streambyte
		m_j = (m_i += 15) + m_SBox[m_i]; // Modified SBox Translation
		{ auto T = m_SBox[m_i]; m_SBox[m_i] = m_SBox[m_j]; m_SBox[m_j] = T; }
		return m_SBox[(byte)(m_SBox[m_i] + m_SBox[m_j])];
	}

	void rc4::crypt(             // Crypts a buffer with RC4 cipher (RC4 modification)
		_In_  void*  Buffer,     // The input data to be crypted
		_In_  size_t BufferSize, // The length of the input in bytes
		_Out_ void*  Output      // The output buffer to be filled (can be inplace)
	) {
		while (BufferSize--)
			((byte*)Output)[BufferSize] = ((byte*)Buffer)[BufferSize] ^ prg();
	}
	void rc4::rc4random(        // generates a random datastream using rc4 scheduling
		_Out_ void*  Buffer,    // The buffer to be filled
		_In_  size_t BufferSize // The size of the buffer
	) {
		while (BufferSize--)
			((byte*)Buffer)[BufferSize] = prg();
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