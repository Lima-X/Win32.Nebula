#include "shared.h"

namespace cry {
#pragma region Aes
	BCRYPT_ALG_HANDLE Aes::s_ah;
	size_t Aes::s_nObj = 0;
	alignas(2) uint16 Aes::s_nRefCount = 0;

	Aes::Aes() { // Provides an AES-Algorithim
		if (!(_InterlockedIncrement16((short*)&s_nRefCount) - 1))
			BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_AES_ALGORITHM, nullptr, NULL);
	}
	Aes::Aes(
		_In_reads_opt_(AesKeySize) const byte Key[AesKeySize]
	) : Aes() {
		byte* pKey;
		if (!Key) {
			// Generate Random Aes256 Key
			pKey = (byte*)malloc(AesKeySize);
			CRNG::FillRandom(pKey, AesKeySize);
		} else
			pKey = (byte*)Key;

		BCryptGenerateSymmetricKey(s_ah, &m_kh, nullptr, 0, pKey, AesKeySize, NULL);
		if (!Key)
			free(pKey);
	}
	Aes::Aes(                       // Provides an AES-Algorithim and imports a key
		_In_     const void* pBlob, // Key (can be wrapped if parm:2 is notnull) to Import
		_In_opt_ const Aes*  pIKey  // Aes-Class with Key used to import
	) : Aes() {
		if (!s_nObj) {
			size_t nResult;
			BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (byte*)&s_nObj, sizeof(s_nObj), (ulong*)&nResult, NULL);
		} if (!m_pObj)
			m_pObj = malloc(s_nObj);

		if (pIKey)
			BCryptImportKey(s_ah, pIKey->m_kh, BCRYPT_AES_WRAP_KEY_BLOB, &m_kh, (uchar*)m_pObj, s_nObj, (uchar*)pBlob, AesWrappedBlob, NULL);
		else
			BCryptImportKey(s_ah, NULL, BCRYPT_KEY_DATA_BLOB, &m_kh, (uchar*)m_pObj, s_nObj, (uchar*)pBlob, AesBlobSize, NULL);
	}
	Aes::~Aes() {
		BCryptDestroyKey(m_kh);
		if (m_pObj) {
			SecureZeroMemory(m_pObj, s_nObj);
			free(m_pObj);
		}
		if (!_InterlockedDecrement16((short*)&s_nRefCount))
			BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status Aes::ExportWrappedKey( // Export Key wrapped with loaded key
		_In_  const Aes&  pWrap,  // Key to Wrap and Export
		_Out_       void* pBlob   // Output (has to be the size of AesWrappedBlob)
	) {
		size_t nSize;
		status s = BCryptExportKey(pWrap.m_kh, m_kh, BCRYPT_AES_WRAP_KEY_BLOB, (byte*)pBlob, AesWrappedBlob, (ulong*)&nSize, NULL);
		return !s && nSize ? nSize : -1;
	}
	status Aes::ValidateKey( // Checks if a Key can decrypt sampledata without opening a plaintext attack
		_In_ void* pData     // Sampledata to Decrypt (has to be 512-Bytes in total)
	) {
		return 0;
	}

	inline status Aes::AesCrypt(
		_In_             void*  pData,
		_In_             size_t nData,
		_In_opt_         void*  pIv,
		_Out_            void*  pRaw,
		_In_range_(0, 1) uint8  cn
	) {
		static size_t nSize = 0;
		byte Iv[AesBlockSize];
		pIv ? memcpy(Iv, pIv, AesBlockSize)
			: memset(Iv, 0, AesBlockSize);

		// BCryptCallTable
		typedef NTSTATUS(WINAPI* BCrypt)(
			_Inout_                                         BCRYPT_KEY_HANDLE hKey,
			_In_reads_bytes_opt_(cbInput)                   PUCHAR            pbInput,
			_In_                                            ULONG             cbInput,
			_In_opt_                                        VOID*             pPaddingInfo,
			_Inout_updates_bytes_opt_(cbIV)                 PUCHAR            pbIV,
			_In_                                            ULONG             cbIV,
			_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR            pbOutput,
			_In_                                            ULONG             cbOutput,
			_Out_                                           ULONG*            pcbResult,
			_In_                                            ULONG             dwFlags
		);
		static constexpr BCrypt BCryptCall[] = {
			BCryptEncrypt, BCryptDecrypt
		};

		status s;
		if (pRaw) {
			s = BCryptCall[cn](m_kh, (uchar*)pData, nData, nullptr, (uchar*)pIv, AesBlockSize, (uchar*)pRaw, nSize, (ulong*)&nSize, NULL);
			nSize = 0;
		} else
			s = BCryptCall[cn](m_kh, (uchar*)pData, nData, nullptr, (uchar*)pIv, AesBlockSize, nullptr, 0, (ulong*)&nSize, NULL);

		return s && nSize ? nSize : -2;
	}

	status Aes::AesEncrypt(_In_ void* pData, _In_ size_t nData, _In_opt_ void* pIv, _Out_ void* pRaw) {
		return AesCrypt(pData, nData, pIv, pRaw, 0);
	}
	status Aes::AesDecrypt(_In_ void* pData, _In_ size_t nData, _In_opt_ void* pIv, _Out_ void* pRaw) {
		return AesCrypt(pData, nData, pIv, pRaw, 1);
	}

	void Aes::ConvertRawKeyToBlob(
		_In_  byte  pKey[AesKeySize],
		_Out_ void* pBlob
	) {
		// Hacks together a AesKeyBlob by putting together a header and and appending the Key
		BCRYPT_KEY_DATA_BLOB_HEADER kdbh = { BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, Aes::AesKeySize };
		memcpy(pBlob, &kdbh, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
		memcpy((void*)((ptr)pBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)), pKey, Aes::AesKeySize);
	}
#pragma endregion

	// TODO: Use Ansistrings internaly then convert to Unicode,
	//       embed strings as directly (hex strings implemented as "\x??")
	DEPRECATED PCWSTR EDecryptString(
		_In_  PCSTR   pString,
		_Out_ size_t* nResult
	) {
		*nResult = strlen(pString);
		alg::Base64A b64(alg::IBase64ObfuscatedTableCbA);
		status nData = b64.EBase64Decode(pString, *nResult, nullptr);
		void* pData = nullptr;
		if (!(nData < 0))
			pData = malloc(nData);
		b64.EBase64Decode(pString, *nResult, pData);

		void* pIv = malloc(16);
		ZeroMemory(pIv, 16);
		PCWSTR sz = 0;// = (PCWSTR)(g_PIB->sCry.EK->IAesDecrypt(pData, *nResult, pIv, nResult));
		free(pIv);
		free(pData);

		return sz;
	}

#pragma region Compression (Cabinet)
	class ICab
		: protected Hash {
	public:
		virtual status IPress(
			_In_      void*  pData,
			_In_      size_t nData,
			_Out_opt_ void*  pOut
		) = 0;

	protected:
		COMPRESSOR_HANDLE__* m_ch;
	};

	class Compressor
		: private ICab {
	public:
		Compressor() {
			CreateCompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &m_ch);
		}
		~Compressor() {
			CloseCompressor(m_ch);
		}

		status IPress(              // Compresses Data into a cab format
			_In_      void*  pData, // Data to be compressed
			_In_      size_t nData, // Sizeof Data to be compressed
			_Out_opt_ void*  pOut   // Output Buffer to be filled with compressed data (if nullptr: will calculate necessary space)
		) override {
			static size_t nSize = 0;
			status s;

			if (pOut) {
				HashData(pData, nData);
				HashFinalize();
				memcpy(pOut, &m_Hash, sizeof(hash));
				s = Compress(m_ch, pData, nData, (void*)((ptr)pOut + sizeof(hash)), nSize, (SIZE_T*)&nSize);
			} else
				s = Compress(m_ch, pData, nData, nullptr, 0, (SIZE_T*)&nSize);
			return s ? nSize + sizeof(hash) : (pOut ? -1 : nSize + sizeof(hash));
		}
	};
	class Decompressor
		: private ICab {
	public:
		Decompressor() {
			CreateDecompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &m_ch);
		}
		~Decompressor() {
			CloseDecompressor(m_ch);
		}

		status IPress(              // Decompresses cabdata into a raw format
			_In_      void*  pData, // Data to be decompressed
			_In_      size_t nData, // Sizeof Data to be decompressed
			_Out_opt_ void*  pOut   // Output Buffer to be filled with raw data (if nullptr: will calculate necessary space)
		) override {
			static size_t nSize = 0;
			status s;

			if (pOut) {
				s = Decompress(m_ch, (void*)((ptr)pData + sizeof(hash)), nData - sizeof(hash), pOut, nSize, (SIZE_T*)&nSize);
				HashData(pOut, nSize);
				HashFinalize();
				if (memcmp(&m_Hash, pData, sizeof(hash)))
					return -1; // Incorrect Hash
			} else
				s = Decompress(m_ch, (void*)((ptr)pData + sizeof(hash)), nData - sizeof(hash), nullptr, 0, (SIZE_T*)&nSize);
			return s ? nSize : (pOut ? -1 : nSize); // Invalid Data
		}
	};
#pragma endregion

#pragma region Hashing
	BCRYPT_ALG_HANDLE Hash::s_ah;
	alignas(2) uint16 Hash::s_nRefCount = 0;
	size_t Hash::s_nObj;

	Hash::Hash() {
		if (!(_InterlockedIncrement16((short*)&s_nRefCount) - 1))
			BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_SHA256_ALGORITHM, nullptr, NULL);
		if (!s_nObj) {
			size_t nResult;
			BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (uchar*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
		}
		m_pObj = malloc(s_nObj);
	}
	Hash::~Hash() {
		if (m_hh)
			BCryptDestroyHash(m_hh);
		free(m_pObj);
		if (!_InterlockedDecrement16((short*)&s_nRefCount))
			BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status Hash::HashData(
		_In_ void* pBuffer,
		_In_ size_t nBuffer
	) {
		status s;
		if (!m_hh)
			s = BCryptCreateHash(s_ah, &m_hh, (uchar*)m_pObj, s_nObj, nullptr, 0, NULL);
		s = BCryptHashData(m_hh, (uchar*)pBuffer, nBuffer, NULL);
		return -!!s;
	}
	status Hash::HashFinalize() {
		status s = BCryptFinishHash(m_hh, (uchar*)&m_Hash, sizeof(hash), NULL);
		s = BCryptDestroyHash(m_hh);
		m_hh = NULL;
		return -!!s;
	}
#pragma endregion

	// Wrapper for the AES, CAB and MD5 -Class' to Pack and Unpack Resources
	class Pack
		: private Aes,
		private Hash {
	public:
	//	Pack(
	//		_In_ const void* pBlob // Wrapped Key to Import
	//	) : Aes(pBlob, &Aes(dat::e_IKey)) {

	//	}
		~Pack() {

		}

		status PackBuffer(
			_In_  void*  pData,
			_In_  size_t nData,
			_Out_ void*  pOut
		) {
			Compressor c;

		}
		status UnPackBuffer(
			_In_  void*  pData,
			_In_  size_t nData,
			_Out_ void*  pOut
		) {
			Decompressor d;
		}


	private:

	};
}


void CryptoTestFunc() {




#pragma region Compression
	byte raw[] = "Test String to be used in crypto test with lenght of: 63 bytes";
	byte compre[0x1000];
	status n;

	{
		cry::Compressor com;
		n = com.IPress(raw, 63, nullptr);
		n = com.IPress(raw, 63, compre);
	}

	byte raw2[63];
	{
		cry::Decompressor dcom;
		dcom.IPress(compre, n, nullptr);
		n = dcom.IPress(compre, n, raw2);
	}

#pragma endregion
}
