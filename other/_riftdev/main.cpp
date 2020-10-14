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
	alignas(2) static volatile uint16 s_nRefCount;
};
alignas(2) volatile uint16 Crc32::s_nRefCount = 0;
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

int main() {
	dbg::Benchmark bm(dbg::Benchmark::Resolution::MICRO);
	bm.Begin();

	char a[] = "Dev";
	dword key[4] = { 0x3253217f, 0xab43e898d, 0x2940be02, 0x21c74e73 };
	XXTea btea(key);

	size_t nt = btea.Encrypt(a, sizeof(a), nullptr);
	byte* out = (byte*)malloc(nt);
	btea.Encrypt(a, sizeof(a), out);

	nt = btea.Decrypt(out, nullptr);
	byte* out2 = (byte*)malloc(nt);
	nt = btea.Decrypt(out, out2);



	void* mem = malloc(1024 * 1024);
	for (int i = 0; i < 1024 * 1024 / 4; i++)
		((ulong*)mem)[i] = rng::Xoshiro::Instance().EXoshiroP();
	xTEA((ulong*)mem, 1024 * 1024 / 4, key);
	xTEA((ulong*)mem, -(1024 * 1024 / 4), key);

#if 0
	__try {
		// *(char*)0 = 0;
	} __except (EXCEPTION_CONTINUE_SEARCH) {}

	void* VEH = AddVectoredExceptionHandler(0, ExceptionHandler);

	__try {
		*(char*)0 = 0;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		BreakPoint();
	}

	RemoveVectoredExceptionHandler(VEH);

	SetUnhandledExceptionFilter(ExceptionHandler);

	__try {
		*(char*)0 = 0;
	} __except (EXCEPTION_CONTINUE_SEARCH) {
		BreakPoint();
	}

	SetUnhandledExceptionFilter(nullptr);
#endif

	uint32 dw = bm.End();
	return 0;

}