// Packing-Crypto-Engine
#include "shared.h"
namespace cry {

#pragma region Hashing
	         handle   BHash::s_BCry;
	BCRYPT_ALG_HANDLE BHash::s_ah;
	volatile u32      BHash::s_nRefCount = 0;
             size_t   BHash::s_nObj;

	BHash::BHash(
		_In_z_ const wchar* AlgorithmId
	) {
		if (!(_InterlockedIncrement((u32*)&s_nRefCount) - 1)) {
			// bcryoap_t BCryptOpenAlgorithmProvider = utl::ImportFunctionByHash()
			// BCryptOpenAlgorithmProvider(&s_ah, AlgorithmId ? AlgorithmId : BCRYPT_SHA256_ALGORITHM, nullptr, NULL);
		}
		if (!s_nObj) {
			size_t nResult;
			// BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (byte*)&s_nObj, sizeof(u32), (dword*)&nResult, NULL);
		}
		m_pObj = HeapAlloc(GetProcessHeap(), 0, s_nObj);
	}
	BHash::~BHash() {
		if (m_hh)
			// BCryptDestroyHash(m_hh);
		HeapFree(GetProcessHeap(), 0, m_pObj);
		if (!_InterlockedDecrement16((short*)&s_nRefCount))
			; // BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status BHash::HashData(
		_In_ void* pBuffer,
		_In_ size_t nBuffer
	) {
		status s = 0; //;
		if (!m_hh)
			// s = BCryptCreateHash(s_ah, &m_hh, (byte*)m_pObj, s_nObj, nullptr, 0, NULL);
		// s = BCryptHashData(m_hh, (byte*)pBuffer, nBuffer, NULL);
		return -!!s;
	}
	status BHash::HashFinalize() {
		status s = 0;// BCryptFinishHash(m_hh, (byte*)&m_Hash, sizeof(sha2), NULL);
		// s = BCryptDestroyHash(m_hh);
		m_hh = NULL;
		return -!!s;
	}
#pragma endregion

	class XPress {
		static constexpr USHORT COMPRESSOR_MODE  = 0x0104;
		static constexpr USHORT COMPRESSOR_CHUCK = 0x1000;

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
		void*     m_WorkSpace;
		u32       m_WorkSpaceSize;
	};
}
