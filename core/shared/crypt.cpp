#include "shared.h"

namespace cry {
#pragma region Aes
	BCRYPT_ALG_HANDLE Aes::s_ah;
	size_t Aes::s_nObj = 0;
	alignas(2) volatile uint16 Aes::s_nRefCount = 0;

	Aes::Aes() { // Provides an AES-Algorithim
		if (!(_InterlockedIncrement16((short*)&s_nRefCount) - 1))
			BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_AES_ALGORITHM, nullptr, NULL);
	}
	Aes::Aes(
		_In_reads_opt_(AesKeySize) byte Key[AesKeySize]
	) : Aes() {
		byte* pKey;
		if (!Key) {
			// Generate Random Aes128 Key
			BCRYPT_ALG_HANDLE ahRng;
			BCryptOpenAlgorithmProvider(&ahRng, BCRYPT_RNG_ALGORITHM, 0, 0);
			pKey = (byte*)malloc(AesKeySize);
			BCryptGenRandom(ahRng, pKey, AesKeySize, 0);
			BCryptCloseAlgorithmProvider(ahRng, 0);
		} else
			pKey = Key;

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
		ALG::Base64A b64(ALG::IBase64ObfuscatedTableCbA);
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

	DEPRECATED void* EUnpackResource(
		_In_  word    wResID,
		_Out_ size_t* nData,
		_In_  Aes*    waes // = g_PIB->sCry.EK
	) {
		// Load Packed Resource
		void* pResource = utl::ELoadResourceW(wResID, L"RT_RCDATA", nData);
		if (!pResource)
			return NULL;

		// Unwarp Key and Import it
		auto* aes = new Aes(((Aes::AESIB*)pResource)->Key, waes);

		// Decrypt Data
		void* pIv = malloc(16);
		// memcpy(pIv, ((Aes::AESIB*)pResource)->Iv, 16);
		// void* pDecrypted = aes->IAesDecrypt(((Aes::AESIB*)pResource)->Data, *nData - sizeof(Aes::AESIB), &pIv, nData);
		free(pIv);
		delete aes;

		// Decompress
		size_t nCompressed = *nData;
		// void* pData = IDecompressLZ(pDecrypted, *nData, nData);
		// SecureZeroMemory(pDecrypted, nCompressed);
		// free(pDecrypted);

		// Check for Corrupted Data
		Md5 pHash;
		// pHash.EHashData(pData, *nData);
		pHash.EFnialize();
		if (pHash.pMd5 == (Md5::hash)(((Aes::AESIB*)pResource)->Hash))
			// return pData;
		// VirtualFree(pData, NULL, MEM_RELEASE);
		return NULL;
	}

#pragma region Compression (Cabinet)

	enum class Mode {
		Compress,
		Decompress
	};

	template<
		_In_range_(0, 1) Mode  M,                            // Specifies which set of Functions to use
		_In_range_(2, 5) dword ALG = COMPRESS_ALGORITHM_LZMS // Specifies which Algorithim to use
	> class Cab {
		const struct FunctionSet {
			typedef BOOL(WINAPI* fpCreate)(
				_In_ DWORD Algorithm,
				_In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
				_Out_ COMPRESSOR_HANDLE__* Handle
				);
			fpCreate Create;
			typedef BOOL(WINAPI* fpClose)(
				_In_ COMPRESSOR_HANDLE__* Handle
				);
			fpClose Close;
			typedef BOOL(WINAPI* fpCall)(
				_In_ COMPRESSOR_HANDLE__* Handle,
				_In_reads_bytes_opt_(InDataSize) LPCVOID InData,
				_In_ SIZE_T InDataSize,
				_Out_writes_bytes_opt_(OutBufferSize) PVOID OutBuffer,
				_In_ SIZE_T OutBufferSize,
				_Out_ PSIZE_T DataSize
				);
			fpCall Call;
		} sets[2] = {
			{ CreateCompressor, CloseCompressor, ::Compress, },
			{ CreateDecompressor, CloseDecompressor, ::Decompress, }
		};

	public:
		Cab() {
			sets[M].fpCreate(ALG, nullptr, &ch);
		}
		~Cab() {
			sets[M].Close(ch);
		}

		status XPress(              // Dec/C -ompresses Cabinet compressed Data
			_In_      void*  pData, // Compressed data to be decompressed
			_In_      size_t nData, // Sizeof Data to be decompressed
			_Out_opt_ void*  pRaw,  // Output Buffer to be filled with raw content (if nullptr: will calculate necessary space needed)
			_In_      Mode   mPress // Specifies if the function should compress or decompress
		) {
			static size_t nSize = 0;
			status s;

			if (pRaw) {
				s = sets[M].Call(ch, pData, nData, pRaw, nSize, (SIZE_T*)&nSize);
				nSize = 0;
			} else
				s = sets[M].Call(ch, pData, nData, nullptr, 0, (SIZE_T*)&nSize);
			return s && nSize ? nSize : -1;
		}
		status AllocXPress(    // Wrapps Decompress method and directly returns allocated Buffer
			_In_     void*  pData, // See Decompress() method
			_In_     size_t nData, //
			_Outref_ void*& pRaw   // Local pointer to point to the newly allocated Buffer
		) {
			size_t nSize = XPress(pData, nData, nullptr);
			pRaw = VirtualAlloc(nullptr, (SIZE_T)nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (!pRaw)
				return -1;
			status s = XPress(pData, nData, pRaw);
			if (s <= 0) {
				VirtualFree(pRaw, 0, MEM_RELEASE);
				return -2;
			}

			dword dw;
			VirtualProtect(pRaw, nSize, PAGE_READONLY, &dw);
			return nSize;
		}
		void FreeXPress( // Frees a Buffer Allocated by AllocDecompress() method
			_In_ void* ptr   // ptr to be freed
		) {
			VirtualFree(ptr, 0, MEM_RELEASE);
		}

	private:
		COMPRESSOR_HANDLE__ *ch;
	};
#pragma endregion

#pragma region Md5
	BCRYPT_ALG_HANDLE Md5::s_ah;
	int Md5::s_nRefCount;
	size_t Md5::s_nObj;

	Md5::Md5() {
		if (!s_nRefCount++)
			BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
		if (!s_nObj) {
			size_t nResult;
			BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (uchar*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
		}
		m_pObj = malloc(s_nObj);
	}
	Md5::~Md5() {
		if (m_hh)
			BCryptDestroyHash(m_hh);
		free(m_pObj);
		if (!--s_nRefCount)
			BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status Md5::EHashData(
		_In_ void* pBuffer,
		_In_ size_t nBuffer
	) {
		status s;
		if (!m_hh)
			s = BCryptCreateHash(s_ah, &m_hh, (uchar*)m_pObj, s_nObj, nullptr, 0, NULL);
		s = BCryptHashData(m_hh, (uchar*)pBuffer, nBuffer, NULL);
		return -!!s;
	}
	status Md5::EFnialize() {
		status s = BCryptFinishHash(m_hh, (uchar*)&m_pMd5, sizeof(hash), NULL);
		s = BCryptDestroyHash(m_hh);
		m_hh = NULL;
		return -!!s;
	}
#pragma endregion

	// Wrapper for the AES, CAB and MD5 -Class' to Pack and Unpack Resources
	enum class Mode2 {
		Pack,
		Unpack
	};

	template<
		Mode2 M
	> class Pack
		: private Aes,
		private Cab<M>,
		private Md5 {
	public:
		Pack(
			_In_ const void* pBlob // Wrapped Key to Import
		)
			: Aes(pBlob, &Aes(dat::e_IKey))
		{

		}
		~Pack() {

		}

		status PackBuffer(
			_In_ void* pData,
			_In_ size_t nData,
			_Out_ void* pOut
		) {

		}


	private:

	};
}
