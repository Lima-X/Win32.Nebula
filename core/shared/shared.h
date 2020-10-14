/* This File is shared between the core Projects and provides intercompatibility between them. */
#pragma once
#include "..\..\global\global.h"

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

// Microsoft Detours
#pragma comment(lib, "..\\..\\other\\msDetours\\lib.X86\\detours.lib")
#include "..\..\other\msDetours\include\detours.h"



#ifdef __cplusplus
namespace rng {
	// TODO: Implement a Guard mechanism as this currently does not automatically free the Memory !
	class Xoshiro {
	public:
		// Constructor/Destructor and Signleton Initialization
		Xoshiro(_In_opt_ void* dwState = nullptr);
		~Xoshiro();
		static Xoshiro& Instance();

		// Xoshiro Functions
		dword EXoshiroSS();
		dword EXoshiroP();
		// Uniform int/float Distribution Functions
		uint32 ERandomIntDistribution(_In_ uint32 nMin, _In_ uint32 nMax);
		float ERandomRealDistribution();

	private:
		// State, Sync Opbject (for Singleton) & internal Trampoline
		static CRITICAL_SECTION cs;
		void(Xoshiro::*m_Trampoline)();
		dword m_dwState[4];

		// Internal State manipulation Functions
		dword __forceinline IRotlDw(_In_ dword dw, _In_ uint8 sh) const;
		inline void INext2();
		inline void INext();
	};
}

namespace ALG { /* Base64A Encoder/Decoder, UUID Converters and SigScanner : shared.c */
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
		char m_HexTable[('a' - '0') - 1];
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
		enum Property {
			AesKeySize = 0x10,                                                 // 128-Bit
			AesBlobSize = (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AesKeySize), // 28-Bytes (Dynamic)
			AesWrappedBlob = (8 + AesKeySize),                                    // 24-Bytes (Hardcoded)
			AesBlockSize = 0x10
		};

		// Encrypted File/Resource Header
		struct AESIB {
			byte      Key[Property::AesWrappedBlob]; // Wrapped Aes128 Key (ew, hardcoded size that is not specified by BCrypt's docs (also fuck BCrypt's docs))
			Md5::hash Hash;                           // Md5-Checksum of original File
		};

		Aes(_In_ const void* pBlob, _In_opt_ const Aes* pIKey = nullptr);
		Aes(_In_opt_ byte Key[AesKeySize]);

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

		static BCRYPT_ALG_HANDLE s_ah;
		static size_t s_nObj;
		alignas(2) volatile static uint16 s_nRefCount;
		BCRYPT_KEY_HANDLE m_kh;
		void* m_pObj;
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
		static uint32 m_nRefCounter; // Class Reference Counter
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
		0xd9, 0xbf, 0x99, 0x27, 0x18, 0xca, 0x6a, 0xf6,
		0xb4, 0xd5, 0xd4, 0x67, 0x4e, 0xf5, 0xf9, 0x01
	};
	// KillSwitch Data Hash
	DEPRECATED constexpr byte e_KillSwitchHash[sizeof(cry::Md5::hash)] = {
		0xc5, 0xc9, 0x2b, 0x4e, 0xe2, 0xc4, 0x61, 0x8f,
		0x65, 0x59, 0xf1, 0x98, 0x48, 0xae, 0xf5, 0x3b
	};
}
#endif
