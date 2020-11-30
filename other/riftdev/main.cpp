// This Project is used to code and debug modules outside of the actual riftProject itself
#include "global.h"
#include "shared.h"

void dlist(); // dllist Test
void other(); // other Test



long __stdcall ExceptionHandler(
	EXCEPTION_POINTERS* ExceptionInfo
) {
	BreakPoint();

	return EXCEPTION_CONTINUE_SEARCH;
}

#pragma region CRC32
// Implementation taken from gcc
class Crc32 {
public:
	Crc32() {
		if (!(_InterlockedIncrement16((short*)&s_nRefCount) - 1)) {
			m_pTable = (dword*)malloc(256 * sizeof(*m_pTable));

			uint32 c; uint8 j;
			for (uint16 i = 0; i < 256; i++) {
				for (c = i << 24, j = 8; j > 0; j--)
					c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : (c << 1);
				m_pTable[i] = c;
			}
		}
	}
	~Crc32() {
		if (!_InterlockedDecrement16((short*)&s_nRefCount))
			free(m_pTable);
	}

	uint32 Hash(
		_In_ const void*  buf,
		_In_       size_t len,
		_In_       uint32 crc = 0
	) {
		while (len--) {
			crc = (crc << 8) ^ m_pTable[((crc >> 24) ^ *(byte*)buf) & 255];
			(*(byte**)&buf)++;
		} return crc;
	}

private:
	                  dword* m_pTable;
	alignas(2) static uint16 s_nRefCount;
};
alignas(2) uint16 Crc32::s_nRefCount = 0;
#pragma endregion

#pragma region XXTEA
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z)))
#define DELTA 0x9e3779b9;
status xTEA(
	_Inout_    ulong* v,
	_In_       long   n,
	_In_ const ulong  k[4]
) {
	ulong e, s = 0, y = v[0], z;
	 long p, q;

	if (n > 1) { // Encrypt
		z = v[n - 1];
		q = 6 + 52 / n;
		while (q-- > 0) {
			s += DELTA;
			e = s >> 2 & 3;
			for (p = 0; p < n - 1; p++)
				y = v[p + 1],
				z = v[p] += MX;
			y = v[0];
			z = v[n - 1] += MX;
		} return 0;
	} else if (n < -1) { // Decrypt
		n = -n;
		q = 6 + 52 / n;
		s = q * DELTA;
		while (s != 0) {
			e = s >> 2 & 3;
			for (p = n - 1; p > 0; p--)
				z = v[p - 1],
				y = v[p] -= MX;
			z = v[n - 1];
			y = v[0] -= MX;

			s -= DELTA;
		} return 0;
	} return -1;
}
#pragma endregion Original lightly modified XXTEA

class XXTea
	: private Crc32 {
	struct Hdr {
		size_t nData;      // Stores the total Size of the Container
		struct EDat {      //
			uint32 uCrc;   // Contains a CRC32 Checksum of the raw Data
			byte   Data[]; // Variable Data Array
		} eData;
	};

public:
	XXTea(
		_In_ void* pKey
	) : m_k() {
		memcpy(const_cast<ulong*>(m_k), pKey, 16);
	}

	status Encrypt(              // Encrypts a buffer (returns size of required Buffer)
		_In_ const void*  pData, // Data to be encrypted
		_In_       size_t nData, // Size of Data
		_Out_opt_  void*  pOut   // Buffer to fill (if null: only calculates returnvalue)
	) {
		// Calculate space required for the encryption buffer
		size_t nSize = RoundUpToMulOfPow2(nData, 4);
		nSize = Max(nSize + sizeof(Hdr::eData), 8);

		if (pOut) {
			Hdr* hdr = (Hdr*)pOut;
			hdr->nData = sizeof(Hdr) + nData;              // Store size of total buffer
			hdr->eData.uCrc = Hash(pData, nData);	       // store CRC32 checksum of raw data
			memcpy(hdr->eData.Data, pData, nData);         // Move Date into Buffer
			memset((void*)((ptr)&hdr->eData.Data + nData),
				0, (nSize - sizeof(Hdr::eData)) - nData);  // Zero-Pad Data
			encrypt((ulong*)&hdr->eData, nSize / 4);       // Encrypt Buffer Inplace
		}

		return nSize + (sizeof(Hdr) - sizeof(Hdr::eData));
	}
	status Decrypt(				 // Decrypts a buffer (returns size of decrypted Data)
		_In_ const void*  pData, // Data to be decrypted
		_Out_opt_  void*  pOut   // Buffer to fill (if null: function returns required buffer size)
	) {
		static constexpr size_t nBlock = (sizeof(Hdr) - sizeof(Hdr::eData)); // Calculate Datablock Size
		if (pOut) {
			size_t n = ((Hdr*)pData)->nData - nBlock;         // Calculate content Size
			memcpy(pOut, (void*)&((Hdr*)pData)->eData, n);    // Move Data into Buffer
			decrypt((ulong*)pOut, n / 4);                     // Decrypt Buffer Inplace

			n = ((Hdr*)pData)->nData - sizeof(Hdr);
			uint32 crc = Hash((((Hdr::EDat*)pOut)->Data), n); // Hash decrypted Data
			if (crc == ((Hdr::EDat*)pOut)->uCrc) {
				memmove(pOut, ((Hdr::EDat*)pOut)->Data, n);   // Realign Data to Buffer
				return n;
			} else
				return -1; // Invalid CRC, discard Buffer
		} else
			return RoundUpToMulOfPow2(((Hdr*)pData)->nData - sizeof(Hdr), 4) + nBlock;
	}

	status EncryptInplace(              // Encrypts a buffer (returns size of required Buffer)
		_Inout_opt_ const void*  pData, // Data to be encrypted (if null: only calculate required space)
		_In_              size_t nData  // Size of Data
	) {}
	status DecryptInplace(        // Decrypts a buffer (returns size unencrypted Data)
		_Inout_ const void* pData // Data to be encrypted
	) {}

private:
#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (m_k[(p & 3) ^ e] ^ z)))
	static constexpr ulong uDelta = 0x9e3779b9;
	void encrypt(
		_Inout_ ulong* v,
		_In_    int32  n
	) {
		ulong p,
			s = 0,
			y = v[0],
			z = v[n - 1],
			q = 6 + 52 / n;
		while (q-- > 0) {
			s += uDelta;
			ulong e = s >> 2 & 3;
			for (p = 0; p < n - 1; p++)
				y = v[p + 1],
				z = v[p] += MX;
			y = v[0];
			z = v[n - 1] += MX;
		}
	}
	void decrypt(
		_Inout_ ulong* v,
		_In_    int32  n
	) {
		ulong p, z,
			y = v[0],
			q = 6 + 52 / n,
			s = q * uDelta;
		while (s != 0) {
			ulong e = s >> 2 & 3;
			for (p = n - 1; p > 0; p--)
				z = v[p - 1],
				y = v[p] -= MX;
			z = v[n - 1];
			y = v[0] -= MX;

			s -= uDelta;
		}
	}
#undef MX

	const dword m_k[4];
};

#include "shared.h"

#if 0
SigScan::SigScan(
	_In_ const void* pData,
	_In_       size_t nData,
	_In_ const void* pSig,
	_In_ const char* szMask
)
	: m_pData(pData),
	m_nData(nData),
	m_pSig(pSig),
	m_nSig(strlen(szMask)
) {
	// Allocate and calculate Mask
	size_t nMask = RoundUpToMulOfPow2(m_nSig, 8) / 8;
	m_pMask = (byte*)malloc(nMask);
	memset(m_pMask, 0, nMask);
	for (size_t i = 0; i < m_nSig; i++)
		if (szMask[i] != '?')
			m_pMask[i / 8] |= 1 << (i % 8);
}
SigScan::~SigScan() {
	free(m_pMask);
}

void* SigScan::FindSig() {
	while (m_nData - m_nSig) {
		size_t i;
		for (i = 0; i < m_nSig; i++)
			if (((m_pMask[m_nSig / 8] >> (7 - i % 8)) & 1) && ((byte*)m_pData)[i] != ((byte*)m_pSig)[i])
				break;

		if (i >= m_nSig)
			return (void*)((*(ptr*)&m_pData) - 1);
		(*(ptr*)&m_pData)++, m_nData--;
	}

	return nullptr;
}
#endif






class SigScan2 {
public:
	struct Sig {
		size_t nSize;
		byte   SigAndMask[];
	};

	SigScan2(
		_In_ byte   Sig[],
		_In_ byte   Mask[],
		_In_ size_t nSig
	)
		: m_nSig(nSig)
	{
		m_Sig = (byte*)malloc(nSig);
		memcpy(m_Sig, Sig, nSig);
		size_t t = RoundUpToMulOfPow2(nSig, 8) / 8;
		m_Mask = (byte*)malloc(t);
		memcpy(m_Mask, Mask, t);
	}
	~SigScan2() {
		free(m_Sig);
		free(m_Mask);
	}

	// Format: "XX XX ? XX"
	static status ConvertFromIdaSigA(   // Converts a IdaSig to a RiftInternalSig
		_In_z_    const char* szIdaSig, // The IdaSig String to convert
		_Out_opt_       Sig*  sBuf      // The Output buffer to fill with the compact Sig (if null returns needed Size)
	) {
		return 0;
	}

	// Format: "\xXX\xXX\x00\xXX, xx?x"
	static status ConvertFromCodeSigA(   // Converts a CodeSig to a RiftInternalSig
		_In_z_    const char* szCodeSig, // The CodeSig String to convert
		_Out_opt_       Sig* sBuf       // The Output buffer to fill with the compact Sig (if null returns needed Size)
	) {
		size_t nLen = 0;
		const char* sz = szCodeSig;
		while (*sz != ',')
			nLen++, sz += 4;

		if (sBuf) {
			sBuf->nSize = nLen;
			byte* pBuf = (byte*)((ptr)sBuf + sizeof(Sig));
			for (size_t i = 0; i < nLen; i++)
				pBuf[i] = ConvertToByteA(szCodeSig + 4 * i + 2);
			memset(pBuf + nLen, 0, RoundUpToMulOfPow2(nLen, 8) / 8);
			for (size_t i = 0; i < nLen; i++)
				if ((szCodeSig + nLen * 4 + 2)[i] == 'x')
					(pBuf + nLen)[i / 8] |= 1 << (7 - i % 8);
		}

		return sizeof(Sig) + nLen + RoundUpToMulOfPow2(nLen, 8) / 8;
	}

	status ScanRegion(
		_In_ void* pAddr,
		_In_ size_t nSize
	) {
		return 0;
	}

private:
	static byte ConvertToByteA(
		_In_ const char* szPair
	) {
		return (*szPair >= 'A' ? *szPair - '7' : *szPair - '0') << 4
			| (*++szPair >= 'A' ? *szPair - '7' : *szPair - '0');
	}

	byte* m_Sig;
	byte* m_Mask;
	size_t m_nSig;
};

// Microsoft Detours
#ifdef _M_AMD64
#pragma comment(lib, "..\\..\\other\\detours\\lib.X64\\detours.lib")
#elif _M_IX86
#pragma comment(lib, "..\\..\\other\\detours\\lib.X86\\detours.lib")
#endif
#include "..\other\detours\detours.h"



int main() {
	void* func = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(func, &mbi, sizeof(mbi));

here:
	HMODULE rk = LoadLibraryW(L"D:\\visualstudio\\repos\\Win32.rift\\out\\bin\\riftrk64.dll");
	typedef long(__stdcall* DbgSetupForLoadLib)(_In_opt_ void* lpParameter);
	DbgSetupForLoadLib init = (DbgSetupForLoadLib)
		GetProcAddress(rk, "DbgSetupForLoadLib");


#if 0
	init(rk);

	rkc = FindWindowExW(HWND_MESSAGE, NULL, L"rift-RootKit(rk)/process:0000", nullptr);
	SendMessageW(rkc, WM_COPYDATA, NULL, (LPARAM)&package);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	CloseHandle(hSnap);

	__debugbreak();
#endif

	dword pid = 8708;
	COPYDATASTRUCT package{ 0, 4, &pid };
	HWND rkc;

	ptr modulebase = 0x7ffe07030000;
	ptr offset = (ptr)init - (ptr)rk;
	offset += modulebase;


	// Working now
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)offset, (void*)modulebase, 0, 0);

	rkc = FindWindowExW(HWND_MESSAGE, NULL, L"rift-RootKit(rk)/process:0000", nullptr);

	const wchar* File = L"D:\\visualstudio\\repos\\Win32.rift\\out\\bin\\riftrk64.dll";

	package = { 1<<4, 54 * sizeof(wchar), &File };
	SendMessageW(rkc, WM_COPYDATA, NULL, (LPARAM)&package);

//	package = { 4, 4, &targetpid };
//	SendMessageW(rkc, WM_COPYDATA, NULL, (LPARAM)&package);

	return 0;
}