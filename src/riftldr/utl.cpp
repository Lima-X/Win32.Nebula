// Utilities and more ;)
#include "ldr.h"

namespace utl {
	// TODO: proper 2way function has to be implemented
	DEPRECATED_STR("Old Pointer Encoding function (this one works both ways and is not optimal for the job)")
	void* CodePointer(
		_In_ void* Pointer
	) {
		return (void*)((ptr)Pointer ^ g_.ProcessCookie);
	}


	poly CryptPointer2(
		_In_ poly x
	) {
		// encode 2.0:
		// usermode memory has a addressrange of 0x0000xxxxxxxxxxxx
		// the upper 16bits are reserved for kernel (0xffffxxxxxxxxxxxx,
		// technically we have 17 bits because usermode is still limited to the lower 44bits)
		// we can use those 16 bits in order to store a state used in a lagorithim to encode / decode the object
		// we can also automatically detect if its encoded and therefore automatically select the operation

		// encoded codestate format
		// bbbbb - b           - bbbbb/bbbbb
		// 57rot | encoded bit | 64rot

		dword RtlState;

	#define MX ((x >> 59) & 0x1f) // The offset to rotate | 0xfc00000000000000
	#define IX (59 - MX)          // Mathematical inverse MX
		if (x >> 58 & 1) { // encoded pointer -> decode
			x ^= g_.ProcessCookie;

			// rotate [57:0] left
			u64 valp1 = (x << MX) & 0x3ffffffffffffff;
			u64 valp2 = (x >> IX) & ((u64)1 << MX) - 1;
			x = (valp1 | valp2) | x & 0xfc00000000000000;

			// Translation and removal of state
			x = (u64)_rotr(x, (x >> 53) & 0x1f) | x & 0xffffffff00000000;             // 0x03e0000000000000 | 0x00000000>>>>>>><
			x = (u64)_rotl(x >> 16, (x >> 48) & 0x1f) << 16 | x & 0xffff00000000ffff; // 0x001f000000000000 | 0x0000><<<<<<<0000
			x &= 0x0000ffffffffffff;
		} else { // normal pointer -> encode
			// Translation and state introduction
			x |= (u64)RtlRandomEx(&RtlState) << 48;                                   // x[63:48] = Random
			x = (u64)_rotr(x >> 16, (x >> 48) & 0x1f) << 16 | x & 0xffff00000000ffff; // 0x001f000000000000 | 0x0000>>>>>>><0000
			x = (u64)_rotl(x, (x >> 53) & 0x1f) | x & 0xffffffff00000000;             // 0x03e0000000000000 | 0x00000000><<<<<<<

			// rotate [57:0] right
			u64 valp1 = (x >> MX) & 0x3ffffffffffffff;
			u64 valp2 = (x << IX) & (((u64)1 << MX) - 1 << IX);
			x = (valp1 | valp2) | x & 0xfc00000000000000;

			// Finalize (enable encoded bit)
			x |= (u64)1 << 58;
			x ^= g_.ProcessCookie & ~((u64)1 << 58);
		}
	#undef IX
	#undef MX

		return x;
	}

	handle EncodePointer(
		_In_ void* Pointer
	) {



	// handle = ptr ^ Cookie
	// t = Cookie >> COffset & 0x3f
	// rol(handle, t)
	//	return (handle)_rotl64((u64)Pointer ^ g_.ProcessCookie,
	//		g_.ProcessCookie >> g_.CookieOffset & 0x3f);
		return 0;
	}
	void* DecodePointer(
		_In_ handle Handle
	) {
		return (void*)(_rotr64((u64)Handle, g_.ProcessCookie)
			^ g_.ProcessCookie >> g_.CookieOffset & 0x3f);
	}


	status GenerateSessionId(
		_Out_ u64& SessionId
	) {
		handle m_Heap = GetProcessHeap();
		SessionId = Fnv64OffsetBasis;

		const dword ProviderSignatures[] = { 'ACPI', 'FIRM', 'RSMB' };
		for (auto i = 0; i < 3; i++) {
			// Enumerate table entries
			size_t TableIdSize = EnumSystemFirmwareTables(ProviderSignatures[i], nullptr, 0);
			dword* TableId = (dword*)HeapAlloc(m_Heap, 0, TableIdSize);
			EnumSystemFirmwareTables(ProviderSignatures[i], TableId, TableIdSize);

			for (auto j = 0; j < TableIdSize / sizeof(dword); j++) {
				// Get firmware tables
				size_t TableSize = GetSystemFirmwareTable(ProviderSignatures[i], TableId[j], nullptr, 0);
				void* Table = HeapAlloc(m_Heap, 0, TableSize);
				GetSystemFirmwareTable(ProviderSignatures[i], TableId[j], Table, TableSize);

				// Hash Table
				Fnv1a64Hash(Table, TableSize, SessionId);
				HeapFree(m_Heap, 0, Table);
			}

			HeapFree(m_Heap, 0, TableId);
		}

		return SUCCESS;
	}

	// this generates a true hardware Id by parsing the table
	// and only hashing specific entries (also avoiding specific fields)
	status GenerateHardwareId(
		_Out_ u64& HardwareId
	) {
		handle m_Heap = GetProcessHeap();
		HardwareId = Fnv64OffsetBasis;

		// Get SMBios Table
		size_t TableSize = GetSystemFirmwareTable('RSMB', 0x0000, nullptr, 0);
		auto RawSmBiosTable = HeapAlloc(m_Heap, 0, TableSize);
		GetSystemFirmwareTable('RSMB', 0x0000, RawSmBiosTable, TableSize);

		// Get First Entry
		typedef struct SmBiosTableHeader {
			byte bType;
			byte nLength;
			WORD wHandle;
		};
		auto Entry = (SmBiosTableHeader*)((ptr)RawSmBiosTable + 8);

		// Walk Entries
		while (Entry->bType != 127) {
			// Start of String Table and Get Entry Size and next Entry Address
			auto StringTable = (void*)((ptr)Entry + Entry->nLength);
			while (*(word*)StringTable != 0x0000)
				((ptr&)StringTable)++;
			size_t EntrySize = ((ptr)StringTable + 2) - (ptr)Entry;

			// Test if Entry should be hashed
			const byte DataEntryTypes[] = {
				0x00, // BIOS            : O
				0x04, // Processor       : S
				0x07, // Cache           : O
				0x08, // Ports           : O
				0x09, // Slots           : O
				0x10, // Physical Memory : O
				0x11, // Memory Devices  : O
				0x02  // Baseboard       : X
			};
			for (auto i = 0; i < sizeof(DataEntryTypes); i++) {
				if (Entry->bType == DataEntryTypes[i])
					switch (Entry->bType) {
					case 4:
						// Avoid "Current Speed" Field
						Fnv1a64Hash(Entry, 0x16, HardwareId);
						Fnv1a64Hash(Entry + 0x18, EntrySize - 0x18, HardwareId);
						break;

					default:
						Fnv1a64Hash(Entry, EntrySize, HardwareId);
					}
			}

			// Set Address of next Entry
			(ptr&)Entry += EntrySize;
		}

		HeapFree(m_Heap, 0, RawSmBiosTable);
		return SUCCESS;
	}
}
