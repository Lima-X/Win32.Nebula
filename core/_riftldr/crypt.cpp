#include "_riftldr.h"

namespace cry {
#pragma region Aes
	BCRYPT_ALG_HANDLE Aes::s_ah;
	size_t Aes::s_nObj;
	int Aes::s_nRefCount = 0;

	Aes::Aes(
		_In_     void* pBlob,
		_In_opt_ Aes*  pIKey
	) {
		if (!s_ah && !s_nRefCount)
			NTSTATUS nts = BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_AES_ALGORITHM, nullptr, NULL);
		status s;
		if (!s_nObj) {
			size_t nResult;
			s = BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (uchar*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
		}
		m_pObj = malloc(s_nObj);
		if (!pIKey)
			s = BCryptImportKey(s_ah, NULL, BCRYPT_KEY_DATA_BLOB, &m_kh, (uchar*)m_pObj, s_nObj, (uchar*)pBlob, AesBlobSize, NULL);
		else
			s = BCryptImportKey(s_ah, pIKey->m_kh, BCRYPT_AES_WRAP_KEY_BLOB, &m_kh, (uchar*)m_pObj, s_nObj, (uchar*)pBlob, AesWrappedBlob, NULL);
		s_nRefCount++;
	}
	Aes::~Aes() {
		status s = BCryptDestroyKey(m_kh);
		SecureZeroMemory(m_pObj, s_nObj);
		free(m_pObj);
		if (!--s_nRefCount)
			s = BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	// TODO: this has to be implemented and adapted to the new c++ class model for rift
	VOID Aes::ExportWrappedKey(
		_In_  const Aes& pWrap,
		_Out_ void*      pBlob
	) {}
	status Aes::ValidateKey( // Checks if a Key can decrypt sampledata without opening a plaintext attack
		_In_ void* pData      // Sampledata to Decrypt (has to be 512-Bytes in total)
	) {
		return 0;
	}

	/* Internal Decryption Subroutine */
	void* Aes::IAesDecrypt(
		_In_  void*   pData,
		_In_  size_t  nData,
		_In_  void*   pIv,
		_Out_ size_t* nResult
	) {
		NTSTATUS nts = BCryptDecrypt(m_kh, (uchar*)pData, nData, nullptr, (uchar*)pIv, 16, NULL, 0, (ulong*)nResult, NULL);
		if (nts)
			return NULL;

		// void* pDecrypted = malloc(*nResult);
		void* pDecrypted = VirtualAlloc(nullptr, *nResult, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
		nts = BCryptDecrypt(m_kh, (uchar*)pData, nData, nullptr, (uchar*)pIv, 16, (uchar*)pDecrypted, *nResult, (ulong*)nResult, NULL);
		if (nts) {
			free(pDecrypted);
			return NULL;
		}

		return pDecrypted;
	}
#pragma endregion

	VOID IConvertKeyToBlob(
		_In_  uuid* pKey,
		_Out_ void* pBlob
	) {
		// Actually implement Bcrypt Import and Export instead of doing it like this....
		BCRYPT_KEY_DATA_BLOB_HEADER kdbh = { BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, AesKeySize };
		memcpy(pBlob, &kdbh, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
		memcpy((void*)((ptr)pBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)), pKey, AesKeySize);
	}

	/* String Decryption */
	// TODO: Use Ansistrings internaly then convert to Unicode
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
		PCWSTR sz = (PCWSTR)(g_PIB->sCry.EK->IAesDecrypt(pData, *nResult, pIv, nResult));
		free(pIv);
		free(pData);

		return sz;
	}

	/* Resource Unpacking */
	void* IDecompressLZ(
		_In_  void* pData,
		_In_  size_t  nData,
		_Out_ size_t* nResult
	) {
		COMPRESSOR_HANDLE ch;
		if (CreateDecompressor(COMPRESS_ALGORITHM_LZMS, NULL, &ch)) {
			Decompress(ch, pData, nData, NULL, 0, (SIZE_T*)nResult);
			void* pDecompressed = VirtualAlloc(nullptr, (SIZE_T)nResult, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
			if (pDecompressed) {
				if (Decompress(ch, pData, nData, pDecompressed, (SIZE_T)nResult, (SIZE_T*)nResult)) {
					CloseDecompressor(ch);
					return pDecompressed;
				}
			}
		}

		return NULL;
	}
	void* EUnpackResource(
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
		memcpy(pIv, ((Aes::AESIB*)pResource)->Iv, 16);
		void* pDecrypted = aes->IAesDecrypt(((Aes::AESIB*)pResource)->Data, *nData - sizeof(Aes::AESIB), &pIv, nData);
		free(pIv);
		delete aes;

		// Decompress
		size_t nCompressed = *nData;
		void* pData = IDecompressLZ(pDecrypted, *nData, nData);
		SecureZeroMemory(pDecrypted, nCompressed);
		free(pDecrypted);

		// Check for Corrupted Data
		Md5 pHash;
		pHash.EHashData(pData, *nData);
		pHash.EFnialize();
		if (pHash.pMd5 == (Md5::hash)(((Aes::AESIB*)pResource)->Hash))
			return pData;
		VirtualFree(pData, NULL, MEM_RELEASE);
		return NULL;
	}

#pragma region Md5
	BCRYPT_ALG_HANDLE Md5::s_ah;
	int Md5::s_nRefCount;
	size_t Md5::s_nObj;

	Md5::Md5() {
		status s;
		if (!s_ah && !s_nRefCount)
			s = BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
		if (!s_nObj) {
			size_t nResult;
			s = BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (uchar*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
		}
		m_pObj = malloc(s_nObj);
		s_nRefCount++;
	}
	Md5::~Md5() {
		status s;
		if (m_hh)
			s = BCryptDestroyHash(m_hh);
		free(m_pObj);
		if (!--s_nRefCount)
			s = BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status Md5::EHashData(
		_In_ void* pBuffer,
		_In_ size_t nBuffer
	) {
		status s;
		if (!m_hh)
			s = BCryptCreateHash(s_ah, &m_hh, (uchar*)m_pObj, s_nObj, nullptr, 0, NULL);
		s = BCryptHashData(m_hh, (uchar*)pBuffer, nBuffer, NULL);
		return s;
	}
	status Md5::EFnialize() {
		status s = BCryptFinishHash(m_hh, (uchar*)&m_pMd5, sizeof(hash), NULL);
		s = BCryptDestroyHash(m_hh);
		m_hh = NULL;
		return s;
	}
#pragma endregion
}
