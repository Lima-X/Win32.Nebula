/* This File is shared between multiple Projects and provides intercompatibility between them. */
#pragma once

#include "..\..\global\global.h"

// #define ROUNDUP_MULTIPLE_BIT(num, mul) (((num + (mul - 1)) & ((size_t)-mul)))
// #define ROUNDUP_MULTIPLE_MUL(num, mul) (((num + (mul - 1)) / mul) * mul)

/* BCrypt */
#define AES_KEY_SIZE    0x10                                                 // 128-Bit
#define AES_BLOB_SIZE   (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE) // 28-Bytes (Dynamic)
#define AES_WARPED_SIZE (8 + AES_KEY_SIZE)                                   // 24-Bytes (Hardcoded)

namespace rng {
	class Xoshiro {
	public:
		// Constructor/Destructor and Signleton Initialization
		Xoshiro(_In_opt_ dword* dwState = nullptr);
		~Xoshiro();
		static Xoshiro* Instance();

		// Xoshiro Functions
		dword EXoshiroSS();
		dword EXoshiroP();
		// Uniform int/float Distribution Functions
		uint32 ERandomIntDistribution(_In_ uint32 nMin, _In_ uint32 nMax);
		float ERandomRealDistribution();
	private:
		// State, Sync Opbject (for Singleton) & internal Trampoline
		static Xoshiro* s_xsrInstance;
		static CRITICAL_SECTION cs;
		void(Xoshiro::*m_Trampoline)();
		dword m_dwState[4];

		// Internal State manipulation Functions
		dword __forceinline IRotlDw(_In_ dword dw, _In_ uint8 sh) const;
		inline void INext2();
		inline void INext();
	};
}

namespace alg { /* Base64A Encoder/Decoder, UUID Converters and SigScanner : shared.c */
	// why -A suffix, because these functions work with raw data,
	// also Hex and Base64A don't need Unicode
	// and it would be stupid to use Unicode outside of the programm anyways,
	// as it would just bloat the data
	class Base64A {
	public:
		Base64A(_In_opt_ void(*TableConstructorCbA)(_In_ void *pTable) = nullptr);
		~Base64A();
		status EBase64Encode(_In_ void* pData, _In_ size_t nData, _Out_opt_ PSTR psz, _In_ bool bPad);
		status EBase64Decode(_In_ PCSTR psz, _In_ size_t nsz, _Out_opt_ void* pData);
	private:
		char* pcTable;
	};

	void IBase64ObfuscatedTableCbA(_In_ void* pTable);

	class HexConvA {
	public:
		HexConvA();
		void BinToHex(_In_ void* pData, _In_ size_t nData, _Out_ char* sz);
		void HexToBin(_In_ char* sz, _Out_ void* pOut);

	private:
		char* m_HexTable;
	};
}

namespace utl {
	class SigScan {
	public:
		SigScan(
			_In_ const void*  pData,
			_In_       size_t nData,
			_In_ const void*  pSig,
			_In_ const char*  szMask
		);
		~SigScan();
		void* FindSig();

	private:
		const void* const m_pSig;  // Signature
		      byte*       m_pMask; // Mask (this is a bitfield is generated from szMask)
		const size_t      m_nSig;  // Lenght of Signature (this is implicitly taken through the length of the Mask)
		const void*       m_pData; // Address of Memory to search
		      size_t      m_nData; // Size of Region to search in
	};
}

namespace cry {
	class Md5 {
	public:
		typedef GUID hash;
		Md5();
		~Md5();
		status EHashData(_In_ void* pBuffer, _In_ size_t nBuffer);
		status EFnialize();
		const hash& pMd5 = m_pMd5;
	private:
		static BCRYPT_ALG_HANDLE  s_ah;
		static int                s_nRefCount;
		static size_t             s_nObj;
		       BCRYPT_HASH_HANDLE m_hh;
		       void*              m_pObj;
		       hash               m_pMd5;
	};

	class Aes {
	public:
		// Encrypted File/Resource Header
		struct AESIB {
			byte     Key[AES_WARPED_SIZE]; // Wrapped Aes128 Key (ew, hardcoded size that is not specified by BCrypt's docs (also fuck BCrypt's docs))
			byte     Iv[16];               // Initialization-Vector
			Md5::hash Hash;                 // Md5-Checksum of original File
			byte     Data[];               // Start of encrypted Data
		};

		Aes(_In_ void* pBlob, _In_opt_ Aes* pIKey = nullptr);
		~Aes();
		VOID IWrapKey(_In_ const Aes& pWrap, _Out_ void* pBlob);
		status IValidateKey(_In_ void* pData);
		void* IAesDecrypt(_In_ void* pData, _In_ size_t nData, _In_ void* pIv, _Out_ size_t* nResult);
	private:
		static BCRYPT_ALG_HANDLE s_ah;
		static size_t s_nObj;
		static int s_nRefCount;
		BCRYPT_KEY_HANDLE m_kh;
		void* m_pObj;
	};

	VOID IConvertKeyToBlob(_In_ uuid* pKey, _Out_ void* pBlob);
	DEPRECATED PCWSTR EDecryptString(_In_ PCSTR pString, _Out_ size_t* nResult);
	void* IDecompressLZ(_In_ void* pData, _In_  size_t  nData, _Out_ size_t* nResult);
	// Actuall Declaration close to EoF (End of File)
	// void* EUnpackResource(_In_ word wResID, _Out_ size_t* nData, _In_ Aes* waes = g_PIB->sCry.EK);
}

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

#define UUID_STRLEN (16 * 2 + 4)
VOID EUuidEncodeA(_In_ uuid* pId, _Out_ PSTR pString);
VOID EUuidDecodeA(_In_ PCSTR pString, _Out_ uuid* pId);

typedef struct _SIG { // Signature Block
	void*  pSig;       // Signature
	PCSTR  szMask;     // Mask (to ignore certain Bytes)
	size_t nLength;    // Length of Signature to search
} SIG, * PSIG;
void* ESigScan(_In_ void* pData, _In_ size_t nData, _In_ PSIG sig);

/* Utilities and Other : Utils.c */
PDWORD EGetProcessIdbyName(_In_ PCWSTR pProcessName, _Out_ size_t* nProcesses);

/* Process Information Block (replacment for Global Data) */
// This is kinda deprected now because im using the crt now
// this means i shoudl remove all this NoCRT shit i had before
// and keep everything that is run at Tls-time seperately
struct PIB {
#ifndef _riftutl
	struct {     // Hardware and Session ID's
		uuid HW; // Hardware ID (linked to specific SMBIOS Entries)
		uuid SE; // Session ID (linked to ACPI, FIRM and SMBIOS Information)
	} sID;
	struct {          // Standart Crypto Providers and Key's
		cry::Aes* IK; // Internal deobfuscation Key (used to decrypt .EK and strings, maybe more in the future)
		cry::Aes* EK; // Module decryption Key (used to unwrap the resources specific Key)
	} sCry;
	struct {       // Commandline
		size_t n;  // Number of elements inside the Vector
		PWSTR* v;  // Argument array (Vector)
	} sArg;
#endif
	HANDLE hPh;                  // Process Heap
	struct {                     // Module Information
		HMODULE hM;              // Current Module (BaseAddress)
		WCHAR   szMFN[MAX_PATH]; // Current Module Filename
		WCHAR   szCD[MAX_PATH];  // Current Directory
	} sMod;
};
extern PIB* g_PIB;

// this is so ugly, i cant believe i actually have to do this like this, its just horrible but neccassery,
// because this function declaration requires the struct and a object of that struct to be present
// and the struct reqires the actual namespace, where this would normaly be defined to be present
#ifndef _riftutl
namespace cry { void* EUnpackResource(_In_ word wResID, _Out_ size_t* nData, _In_ Aes* waes = g_PIB->sCry.EK); }
#endif