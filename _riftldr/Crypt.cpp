#include "_riftldr.h"

namespace cry {
	class Aes {
	public:
		Aes(
			_In_     void* pBlob,
			_In_opt_ Aes* pIKey = nullptr
		) {
			if (!s_ah && !s_nRefCount)
				NTSTATUS nts = BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_AES_ALGORITHM, nullptr, NULL);
			status s;
			if (!s_nObj) {
				size_t nResult;
				s = BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (static*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
			}
			m_pObj = malloc(s_nObj);
			if (!pIKey)
				s = BCryptImportKey(s_ah, NULL, BCRYPT_KEY_DATA_BLOB, &m_kh, (static*)m_pObj, s_nObj, (static*)pBlob, AES_BLOB_SIZE, NULL);
			else
				s = BCryptImportKey(s_ah, pIKey->m_kh, BCRYPT_AES_WRAP_KEY_BLOB, &m_kh, (static*)m_pObj, s_nObj, (static*)pBlob, AES_WARPED_SIZE, NULL);
			s_nRefCount++;
		}
		~Aes() {
			status s = BCryptDestroyKey(m_kh);
			SecureZeroMemory(m_pObj, s_nObj);
			free(m_pObj);
			if (!--s_nRefCount)
				s = BCryptCloseAlgorithmProvider(s_ah, NULL);
		}

		// TODO: this has to be implemented and adapted to the new c++ class model for rift
		VOID IWrapKey(
			_In_  const Aes& pWrap,
			_Out_ void* pBlob
		) {}
		status IValidateKey( // Checks if a Key can decrypt sampledata without opening a plaintext attack
			_In_ void* pData // Sampledata to Decrypt (has to be 512-Bytes in total)
		) {}

		/* Internal Decryption Subroutine */
		void* IAesDecrypt(
			_In_  void* pData,
			_In_  size_t  nData,
			_In_  void* pIv,
			_Out_ size_t* nResult
		) {
			NTSTATUS nts = BCryptDecrypt(m_kh, (static*)pData, nData, nullptr, (static*)pIv, 16, NULL, 0, (ulong*)nResult, NULL);
			if (nts)
				return NULL;

			void* pDecrypted = malloc(*nResult);
			nts = BCryptDecrypt(m_kh, (static*)pData, nData, nullptr, (static*)pIv, 16, (static*)pDecrypted, *nResult, (ulong*)nResult, NULL);
			if (nts) {
				free(pDecrypted);
				return NULL;
			}

			return pDecrypted;
		}
	private:
		static BCRYPT_ALG_HANDLE s_ah;
		static size_t s_nObj;
		static int s_nRefCount;
		BCRYPT_KEY_HANDLE m_kh;
		void* m_pObj;
	};

	VOID IConvertKeyToBlob(
		_In_  uuid* pKey,
		_Out_ void* pBlob
	) {
		// Actually implement Bcrypt Import and Export instead of doing it like this....
		BCRYPT_KEY_DATA_BLOB_HEADER kdbh = { BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_KEY_DATA_BLOB_VERSION1, AES_KEY_SIZE };
		memcpy(pBlob, &kdbh, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
		memcpy((void*)((ptr)pBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)), pKey, AES_KEY_SIZE);
	}

	/* String Decryption */
	// TODO: Use Ansistrings internaly then convert to Unicode
	DEPRECATED PCWSTR EDecryptString(
		_In_  PCSTR   pString,
		_Out_ size_t* nResult
	) {
		StringCchLengthA(pString, STRSAFE_MAX_CCH, nResult);
		void* pData = EBase64DecodeA(pString, *nResult, nResult);

		void* pIv = malloc(16);
		ZeroMemory(pIv, 16);
		PCWSTR sz = (PCWSTR)(g_PIB->sCIB.WK->IAesDecrypt(pData, *nResult, pIv, nResult));
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
		_In_  word      wResID,
		_Out_ size_t*   nData,
		_In_  cry::Aes& waes = *g_PIB->sCIB.WK
	) {
		// Load Packed Resource
		void* pResource = ELoadResourceW(wResID, L"RT_RCDATA", (SIZE_T*)nData);
		if (!pResource)
			return NULL;

		// Unwarp Key and Import it
		auto* aes = new cry::Aes(((AESIB*)pResource)->Key, &waes);

		// Decrypt Data
		void* pIv = malloc(16);
		memcpy(pIv, ((AESIB*)pResource)->Iv, 16);
		void* pDecrypted = aes->IAesDecrypt(((AESIB*)pResource)->Data, *nData - sizeof(AESIB), &pIv, nData);
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
		if (!memcmp(&pHash.EGetHash(), &((AESIB*)pResource)->Md5, 16))
			return pData;
		VirtualFree(pData, *nData, MEM_RELEASE);
		return NULL;
	}

	class Md5 {
	public:
		Md5() {
			status s;
			if (!s_ah && !s_nRefCount)
				s = BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_MD5_ALGORITHM, nullptr, NULL);
			if (!s_nObj) {
				size_t nResult;
				s = BCryptGetProperty(s_ah, BCRYPT_OBJECT_LENGTH, (static*)&s_nObj, sizeof(dword), (ulong*)&nResult, NULL);
			}
			m_pObj = malloc(s_nObj);
			s_nRefCount++;
		}
		~Md5() {
			status s;
			if (m_hh)
				s = BCryptDestroyHash(m_hh);
			free(m_pObj);
			if (!--s_nRefCount)
				s = BCryptCloseAlgorithmProvider(s_ah, NULL);
		}

		status EHashData(
			_In_ void* pBuffer,
			_In_ size_t nBuffer
		) {
			status s;
			if (!m_hh)
				s = BCryptCreateHash(s_ah, &m_hh, (static*)m_pObj, s_nObj, nullptr, 0, NULL);
			s = BCryptHashData(m_hh, (static*)pBuffer, nBuffer, NULL);
			return s;
		}
		status EFnialize() {
			if (!m_pMd5)
				m_pMd5 = (md5*)malloc(sizeof(md5));
			status s = BCryptFinishHash(m_hh, (static*)m_pMd5, sizeof(md5), NULL);
			s = BCryptDestroyHash(m_hh);
			m_hh = NULL;
			return s;
		}
		md5& EGetHash() {
			return *m_pMd5;
		}
	private:
		static BCRYPT_ALG_HANDLE s_ah;
		static int s_nRefCount;
		static size_t s_nObj;
		BCRYPT_HASH_HANDLE m_hh;
		void* m_pObj;
		md5* m_pMd5;
	};

#if 0 // already implemented in guiddef.h
	bool ::operator==(const md5& rL, const md5& rR) {
		return !memcmp(*(void**)&rL, *(void**)&rR, sizeof(md5));
	}
	bool ::operator!=(const md5& rL, const md5& rR) {
		!(rL == rR);
	}
#endif
}