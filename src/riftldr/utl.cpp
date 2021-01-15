// Utilities and more ;)
#include "ldr.h"

namespace utl {
	void* CryptPointer(
		_In_ void* Pointer
	) {


		return Pointer;
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
