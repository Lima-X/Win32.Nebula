// Utilities and more ;)
#include "ldr.h"

namespace utl {
	poly CryptPointer(
		_In_ poly x
	) {
		// encode 2.0:
		// usermode memory has a addressrange of 0x0000xxxxxxxxxxxx
		// the upper 16bits are reserved for kernel (0xffffxxxxxxxxxxxx,
		// technically we have 17 bits because usermode is still limited to the lower 44bits)
		// we can use those 16 bits in order to store a state used in a lagorithim to encode / decode the object
		// we can also automatically detect if its encoded and therefore automatically select the operation

		// encoded codestate format
		// bbbbb - b       - bbbbb/bbbbb - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
		// 58rot | encoded | 32/32rot    | 48-Bit Pointer

		dword RtlState;

	#define SX(y) ((x >> y) & 0x1f) // Get 5bits of state on offset
	#define MX    SX(59)            // The offset to rotate (58rot) | 0xfc00000000000000
	#define IX    (58 - MX)         // Mathematical inverse MX (ignore encode bit)
		if (x >> 58 & 1) {
			x ^= g_.ProcessCookie & 0xffffull << 48;                        // Demutate 15bit state
			u64 v1 = (x & 0x03ffffffffffffff) >> MX;                        // 58shift upper
			u64 v2 = (x << IX) & ~(0xfcull << 56);                          // 58shift lower
			x = (v1 | v2) | x & 0xfcull << 56;                              // 58rotr combine
			x ^= g_.ProcessCookie & 0xffffffffffff;                         // Demutate 48bit pointer
			x = (u64)_rotl(x >> 16, SX(48)) << 16 | x & 0xffff00000000ffff; // Untranslate upper 48ptr
			x = (u64)_rotr(x, SX(53)) | x & 0xffffull << 32;                // Untranslate lower 48ptr
		} else {
			// Initial pointer translation and state introduction
			x |= (u64)RtlRandomEx(&RtlState) << 48;                         // x[63:48] = Random
			x = (u64)_rotl(x, SX(53)) | x & 0xffffffff00000000;             // 0x03e0000000000000 | 0x00000000><<<<<<<
			x = (u64)_rotr(x >> 16, SX(48)) << 16 | x & 0xffff00000000ffff; // 0x001f000000000000 | 0x0000>>>>>>><0000

			// Mutate [47:0] (48bit pointer)
			x ^= g_.ProcessCookie & 0x0000ffffffffffff;

			// translate 32/32rotlr state into pointer by 58rotl [57:0]
			u64 v1 = (x << MX) & 0x03ffffffffffffff;
			u64 v2 = (x >> IX) & (1ull << MX) - 1;
			x = (v1 | v2) | x & 0xfc00000000000000; // 0x03ffffffffffffff | 0x03><<<<<<<<<<<<<

			// Finalize by mutating state [63:48 & ^58] and enabling the encoded bitflag
			x = x ^ g_.ProcessCookie & 0xffffull << 48 | 1ull << 58;
		}
	#undef IX
	#undef MX
	#undef SX

		return x;
	}

	struct SYSTEM_FIRMWARE_TABLE_INFORMATION {
		ULONG ProviderSignature;
		ULONG Action;
		ULONG TableID;
		ULONG TableBufferLength;
		UCHAR TableBuffer[];
	};

	status GenerateSessionId(
		_Out_ u64& SessionId
	) {
		handle Heap = GetProcessHeap();
		SessionId = Fnv64OffsetBasis;

		const dword ProviderSignatures[] = { 'ACPI', 'FIRM', 'RSMB' };
		for (auto i = 0; i < 3; i++) {
			// Enumerate table entries
			auto IdentifierTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapAlloc(Heap, 0, 16);
			dword ReturnLength;
			IdentifierTable->ProviderSignature = ProviderSignatures[i];
			IdentifierTable->Action = 0;
			IdentifierTable->TableID = 0;
			IdentifierTable->TableBufferLength = 0;
			auto NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
				IdentifierTable, 16, &ReturnLength);
			if (NtStatus == 0xc0000002) // Not implemented -> skip
				continue;
			if (NtStatus != 0xc0000023) // Buffer insufficient
				return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
			IdentifierTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapReAlloc(Heap,
				0, IdentifierTable, IdentifierTable->TableBufferLength + 16);
			NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
				IdentifierTable, IdentifierTable->TableBufferLength + 16, &ReturnLength);
			if (!NT_SUCCESS(NtStatus))
				return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);

			for (auto j = 0; j < IdentifierTable->TableBufferLength / sizeof(dword); j++) {
				// Get firmware tables
				auto FirmwareTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapAlloc(Heap, 0, 16);
				FirmwareTable->ProviderSignature = ProviderSignatures[i];
				FirmwareTable->Action = 1;
				FirmwareTable->TableID = ((dword*)IdentifierTable->TableBuffer)[j];
				FirmwareTable->TableBufferLength = 0;
				NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
					FirmwareTable, 16, &ReturnLength);
				if (NtStatus != 0xc0000023)
					return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
				FirmwareTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapReAlloc(Heap,
					0, FirmwareTable, FirmwareTable->TableBufferLength + 16);
				NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
					FirmwareTable, FirmwareTable->TableBufferLength + 16, &ReturnLength);
				if (!NT_SUCCESS(NtStatus))
					return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);

				// Hash Table
				Fnv1a64Hash(FirmwareTable->TableBuffer, FirmwareTable->TableBufferLength, SessionId);
				HeapFree(Heap, 0, FirmwareTable);
			}

			HeapFree(Heap, 0, IdentifierTable);
		}

		return SUCCESS;
	}

	// this generates a true hardware Id by parsing the table
	// and only hashing specific entries (also avoiding specific fields)
	status GenerateHardwareId(
		_Out_ u64& HardwareId
	) {
		handle Heap = GetProcessHeap();
		HardwareId = Fnv64OffsetBasis;

		// Get SMBios Table
		auto FirmwareTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapAlloc(Heap, 0, 16);
		FirmwareTable->ProviderSignature = 'RSMB';
		FirmwareTable->Action = 1;
		FirmwareTable->TableID = 0x0000;
		FirmwareTable->TableBufferLength = 0;
		dword ReturnLength;
		auto NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
			FirmwareTable, 16, &ReturnLength);
		if (NtStatus != 0xc0000023)
			return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);
		FirmwareTable = (SYSTEM_FIRMWARE_TABLE_INFORMATION*)HeapReAlloc(Heap,
			0, FirmwareTable, FirmwareTable->TableBufferLength + 16);
		NtStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4c,
			FirmwareTable, FirmwareTable->TableBufferLength + 16, &ReturnLength);
		if (!NT_SUCCESS(NtStatus))
			return S_CREATE(SS_ERROR, SF_CORE, SC_UNKNOWN);

		// Get First Entry
		typedef struct SmBiosTableHeader {
			byte bType;
			byte nLength;
			WORD wHandle;
		};
		auto Entry = (SmBiosTableHeader*)((ptr)FirmwareTable->TableBuffer + 8);

		// Walk Entries
		while (Entry->bType != 127) {
			// Start of String Table and Get Entry Size and next Entry Address
			auto StringTable = (void*)((ptr)Entry + Entry->nLength);
			while (*(word*)StringTable != 0x0000)
				((ptr&)StringTable)++;
			size_t EntrySize = ((ptr)StringTable + 2) - (ptr)Entry;

			// Test if Entry should be hashed
			const byte DataEntryTypes[] = {
				// 0x00, // BIOS            : O
				   0x02, // Baseboard       : X
				   0x04, // Processor       : S
				   0x07, // Cache           : O
				// 0x08, // Ports           : O
				// 0x09, // Slots           : O
				// 0x10, // Physical Memory : O
				// 0x11  // Memory Devices  : O
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

		HeapFree(Heap, 0, FirmwareTable);
		return SUCCESS;
	}
}
