// Utilities and more ;)
#include "ldr.h"

namespace utl {
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

#pragma region Fast DoublyLinkedList Implmentation
DoublyLinkedList::DoublyLinkedList(
	_In_ handle Heap
) : m_MemoryContainer(Heap),
	m_LastEntry(nullptr) {}

handle DoublyLinkedList::AllocateObject( // Allocates an object and links it into the list (can NOT be locked in shared mode)
	_In_ size_t ObjectSize               // The amount of memory to allocate for the object
) {
	LockListExclusive();
	auto Object = AllocateEntryInternal(ObjectSize);
	Object->Misc.EntrySize = ObjectSize | 1ull << 63;
	UnlockList();
	return EncodePointer((void*)Object);
}
handle DoublyLinkedList::ReferenceObject( // References an object and links it into the list (can NOT be locked in shared mode)
	_In_ void* VirtualAddress             // The absolute address of the existing object
) {
	LockListExclusive();
	auto Object = AllocateEntryInternal(0);
	Object->Misc.VirtualAddress = VirtualAddress;
	UnlockList();
	return EncodePointer((void*)Object);
}

void DoublyLinkedList::DestroyObject(
	_In_ handle Object
) {
	LockListExclusive();
	auto CurrentEntry = (ListEntry*)DecodePointer(Object);

	if (CurrentEntry->NextEntry && CurrentEntry->PreviousEntry) {
		// Fix up links (link previous and next entry to each other)
		CurrentEntry->PreviousEntry->NextEntry = CurrentEntry->NextEntry;
		CurrentEntry->NextEntry->PreviousEntry = CurrentEntry->PreviousEntry;
	} else {                                                  // Special Handling incase it is first or last entry
		if (CurrentEntry->NextEntry) {                        // Remove first entry
			CurrentEntry->NextEntry->PreviousEntry = nullptr;
			m_FirstEntry = CurrentEntry->NextEntry;
		} else if (CurrentEntry->PreviousEntry) {             // Remove last entry
			CurrentEntry->PreviousEntry->NextEntry = nullptr;
			m_LastEntry = CurrentEntry->PreviousEntry;
		} else                                                // Remove last existing entry
			m_LastEntry = nullptr;
	}

	HeapFree(m_MemoryContainer, 0, CurrentEntry);
	UnlockList();
}

void* DoublyLinkedList::GetObjectAddress(
	_In_ handle Object
) {
	auto CurrentEntry = (ListEntry*)DecodePointer(Object); // Get real object
	if (CurrentEntry->Misc.EntrySize < 0)                  // Check if local object
		return CurrentEntry + 1;                           // is local object
	return CurrentEntry->Misc.VirtualAddress;              // is referenced object
}
size_t DoublyLinkedList::GetObjectSize(
	_In_ handle Object
) {
	auto CurrentEntry = (ListEntry*)DecodePointer(Object);  // Get real object
	if (CurrentEntry->Misc.EntrySize < 0)                   // Check if local object
		return CurrentEntry->Misc.EntrySize & (~0ull >> 1); // is local object
	return null;                                            // is referenced object
}

handle DoublyLinkedList::GetFirstObject() {
	return m_FirstEntry ? EncodePointer(m_FirstEntry) : null;
}
handle DoublyLinkedList::GetLastObject() {
	return m_LastEntry ? EncodePointer(m_LastEntry) : null;
}
handle DoublyLinkedList::GetNextObject(
	_In_ handle Object
) {
	auto CurrentEntry = (ListEntry*)DecodePointer(Object);
	return CurrentEntry->NextEntry ? EncodePointer(CurrentEntry->NextEntry) : null;
}
handle DoublyLinkedList::GetPreviousObject(
	_In_ handle Object
) {
	auto CurrentEntry = (ListEntry*)DecodePointer(Object);
	return CurrentEntry->PreviousEntry ? EncodePointer(CurrentEntry->PreviousEntry) : null;
}

void DoublyLinkedList::LockListExclusive() {
	if (!TryAcquireSRWLockExclusive(&m_ListLock.SrwLockInternal)) {
		if (m_ListLock.OwningThread == GetCurrentThreadId())
			m_ListLock.ExclusiveRecursionCount++;
		else
			m_ListLock.OwningThread = GetCurrentThreadId();
	}

	m_ListLock.OwningThread = GetCurrentThreadId();
	m_ListLock.ExclusiveModeEnabled = true;
}
void DoublyLinkedList::LockListShared() {
	if (m_ListLock.ExclusiveModeEnabled && m_ListLock.OwningThread == GetCurrentProcessId())
		m_ListLock.ExclusiveRecursionCount++;
	else
		AcquireSRWLockShared(&m_ListLock.SrwLockInternal);
}
void DoublyLinkedList::UnlockList() {
	if (m_ListLock.ExclusiveModeEnabled) {
 		if (m_ListLock.OwningThread == GetCurrentThreadId()) {
			if (m_ListLock.ExclusiveRecursionCount)
				m_ListLock.ExclusiveRecursionCount--;
			else {
				ReleaseSRWLockExclusive(&m_ListLock.SrwLockInternal);
				m_ListLock.ExclusiveModeEnabled = false;
			}
		}
	} else
		ReleaseSRWLockShared(&m_ListLock.SrwLockInternal);
}

DoublyLinkedList::ListEntry* DoublyLinkedList::AllocateEntryInternal( // Allocates an Object an
	_In_ size_t ObjectSize
) {
	// Allocate the Object
	auto Object = (ListEntry*)HeapAlloc(m_MemoryContainer, 0, ObjectSize + sizeof(ListEntry));
	if (!Object)
		return nullptr;

	// Link object into list (instert after last object)
	if (m_LastEntry) {
		m_LastEntry->NextEntry = Object;
		Object->PreviousEntry = m_LastEntry;
		Object->NextEntry = nullptr;
		m_LastEntry = Object;
	} else
		m_FirstEntry = m_LastEntry = Object;
	return Object;
}
#pragma endregion
