/* This File is shared between the core Projects and provides intercompatibility between them. */
#pragma once
#include "global.h"

#ifdef __cplusplus
// C++ Library Headers
#include <cstdio>
#else
// C Library Headers
#include <stdio.h>
#endif

// Windows special Headers
#include <psapi.h>
#include <tlHelp32.h>
#include <shlobj.h>
#include <knownfolders.h>

// Windows unlinked Headers
#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib") // Get rid of this in the future
#include <pathcch.h>
#pragma comment(lib, "shlwapi.lib")
#include <shlwapi.h>
#pragma comment(lib, "wininet.lib")
#include <wininet.h>

#ifdef __cplusplus
namespace rng {
	class CRNG {
	public:
		CRNG();
		~CRNG();

		status FillRandom(_In_ void* pBuf, _In_ size_t nBuf);
	private:
		static            BCRYPT_ALG_HANDLE s_ah;
		alignas(2) static uint16            s_nRefCount;
	};

	// TODO: Implement a Guard mechanism as this currently does not automatically free the Memory !
	class Xoshiro {
		static constexpr size_t nState = sizeof(dword) * 4;
	public:
		// Constructor/Destructor and Signleton Initialization
		Xoshiro(_In_opt_ void* dwState = nullptr);
		static Xoshiro& Instance();
		status Reseed();

		// Xoshiro Functions
		dword XoshiroSS();
		dword XoshiroP();
		// Uniform int/float Distribution Functions
		uint32 RandomIntDistribution(_In_ uint32 nMin, _In_ uint32 nMax);
		float RandomRealDistribution();

	private:
		// Actuall Internal Constructor
		Xoshiro(_In_opt_ void(Xoshiro::* const jmp)(), _In_opt_ void* dwState = nullptr);

		// State, Sync Opbject (for Singleton) & internal Trampoline
		static SRWLOCK Lock;
		void(Xoshiro::* const m_Trampoline)();
		dword m_dwState[4];

		// Internal State manipulation Functions
		dword __forceinline rol32l(_In_ dword dw, _In_ uint8 sh) const;
		inline void GNext();
		inline void Next();
	};
}

namespace alg { /* Base64A Encoder/Decoder, UUID Converters and SigScanner : shared.c */
	// why -A suffix, because these functions work with raw data,
	// Hex and Base64A don't need Unicode
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
		static char s_HexTable[('a' - '0') - 1];
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

	void* ELoadResourceW(_In_ word wResID, _In_ const wchar* pResType, _Out_ size_t* nBufferSize);
}

namespace cry {
	class Hash {
	public:
		struct hash {
			byte hash[32];
		} m_Hash;

		Hash();
		~Hash();
		status HashData(_In_ void* pBuffer, _In_ size_t nBuffer);
		status HashFinalize();
	private:
		alignas(2) static uint16             s_nRefCount;
		           static BCRYPT_ALG_HANDLE  s_ah;
		                  BCRYPT_HASH_HANDLE m_hh;
		                  void*              m_pObj;
		           static size_t             s_nObj;
	};

	class Aes
		: private rng::CRNG {
	public:
		enum Property {
			AesKeySize = 0x20,                                                // 256-Bit
			AesBlobSize = (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AesKeySize), // 44-Bytes (Dynamic)
			AesWrappedBlob = (8 + AesKeySize),                                // 40-Bytes (Hardcoded)
			AesBlockSize = 0x10                                               // 16-Bytes (Standard)
		};

		// Encrypted File/Resource Header
		struct AESIB {
			byte      Key[Property::AesWrappedBlob]; // Wrapped Aes128 Key (ew, hardcoded size that is not specified by BCrypt's docs (also fuck BCrypt's docs))
			Hash::hash Hash;                           // Hash-Checksum of original File
		};

		Aes(_In_ const void* pBlob, _In_opt_ const Aes* pIKey = nullptr);
		Aes(_In_opt_ const byte Key[AesKeySize]);

		~Aes();
		status ExportWrappedKey(_In_ const Aes& pWrap, _Out_ void* pBlob);
		status ValidateKey(_In_ void* pData);
		void* IAesDecrypt(_In_ void* pData, _In_ size_t nData, _In_ void* pIv, _Out_ size_t* nResult);
		status AesDecrypt(_In_ void* pData, _In_ size_t nData, _In_opt_ void* pIv, _Out_ void* pRaw);
		status AesEncrypt(_In_ void* pData, _In_ size_t nData, _In_opt_ void* pIv, _Out_ void* pRaw);


		static void ConvertRawKeyToBlob(
			_In_  byte  pKey[AesKeySize],
			_Out_ void* pBlob
		);

	private:
		Aes();
		inline status AesCrypt(_In_ void* pData, _In_ size_t nData, _In_opt_ void* pIv, _Out_ void* pRaw, _In_range_(0, 1) uint8 cn);

		alignas(2) static uint16            s_nRefCount;
		           static BCRYPT_ALG_HANDLE s_ah;
		           static size_t            s_nObj;
		                  BCRYPT_KEY_HANDLE m_kh;
		                  void*             m_pObj;
	};

	VOID IConvertKeyToBlob(_In_ uuid* pKey, _Out_ void* pBlob);
	DEPRECATED PCWSTR EDecryptString(_In_ PCSTR pString, _Out_ size_t* nResult);
	void* IDecompressLZ(_In_ void* pData, _In_  size_t  nData, _Out_ size_t* nResult);
	void* EUnpackResource(_In_ word wResID, _Out_ size_t* nData, _In_ Aes* waes);
}

namespace con {
	class Console {
	public:
		Console(_In_ dword pId = NULL);
		~Console();

		enum class Attributes : byte {                                                      // most significant bit indecates error type
			CON_SUCCESS = FOREGROUND_GREEN,                                                 // 0b00000010
			CON_INFO = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,                 // 0b00000111
			CON_QUEST = 0x40 | FOREGROUND_BLUE | FOREGROUND_INTENSITY,                      // 0b01001001
			CON_ERROR = 0x80 | FOREGROUND_RED | FOREGROUND_INTENSITY,                       // 0b10001100
			CON_WARNING = 0x80 | (FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY // 0b10001110
		};

		status Cls();
		status WaitForSingleInput();
		status WriteW(_In_ word wAttribute);
		status PrintFW(_In_ PCWSTR pText, _In_ Attributes wAttribute = Attributes::CON_INFO, _In_opt_ ...);

	protected:
		// Console Input/Output(/Error) Handle
		static HANDLE m_hConIn;
		static HANDLE m_hConOut;

	private:
		alignas(2) static uint16 m_nRefCounter; // Class Reference Counter
		           static void*  m_pBuffer;     // Temporery Buffer (Pool) that will be used to Format, Get Text and more (multiple of Pagesize)
		           static size_t m_nBuffer;     // The size of data inside the temporery Buffer (Pool)
	};

	class ConsoleGui
		: public Console {
	public:
		void PrintIntro();
	};
}

/* FileSystem */
#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)

// #define UUID_STRLEN (16 * 2 + 4)
// VOID EUuidEncodeA(_In_ uuid* pId, _Out_ PSTR pString);
// VOID EUuidDecodeA(_In_ PCSTR pString, _Out_ uuid* pId);

typedef struct _SIG { // Signature Block
	void*  pSig;       // Signature
	PCSTR  szMask;     // Mask (to ignore certain Bytes)
	size_t nLength;    // Length of Signature to search
} SIG, * PSIG;
void* ESigScan(_In_ void* pData, _In_ size_t nData, _In_ PSIG sig);

/* Process Information Block (replacment for Global Data) */
// This is kinda deprected now because im using the crt now
// this means i shoudl remove all this NoCRT shit i had before
// and keep everything that is run at Tls-time seperately
struct PIB {
#ifndef _riftutl
	struct {                // Hardware and Session ID's
		cry::Hash::hash HW; // Hardware ID (linked to specific SMBIOS Entries)
		cry::Hash::hash SE; // Session ID (linked to ACPI, FIRM and SMBIOS Information)
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
	struct {                     // Module Information
		HMODULE hM;              // Current Module (BaseAddress)
		WCHAR   szMFN[MAX_PATH]; // Current Module Filename
		WCHAR   szCD[MAX_PATH];  // Current Directory
	} sMod;
};


namespace dat {
	/* The Current AesInternalKey used to decrypt Internal Data,
	   this Key is hardcoded and should not be changed.
	   Changing this Key would requirer to reencrypt all Data that is based on this Key,
	   this includes all obfuscated Strings and even external Resources. */
	constexpr byte e_IKey[cry::Aes::AesKeySize] = {
		0
	};

	// KillSwitch Data Hash
	DEPRECATED constexpr byte e_KillSwitchHash[sizeof(cry::Hash::hash)] = {
		0
	};
}
#endif

// Creates a ServiceCallId
#define SVC_MAKEID(SvcDescriptor, FunctionId) ((uint16)((SvcDescriptor << 12) | (FunctionId & 0x0fff)))