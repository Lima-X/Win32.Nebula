#pragma once
#include "global.h"

// Microsoft Detours
#ifdef _M_AMD64
#pragma comment(lib, "..\\..\\other\\detours\\lib.X64\\detours.lib")
#elif _M_IX86
#pragma comment(lib, "..\\..\\other\\detours\\lib.X86\\detours.lib")
#endif
#include "..\other\detours\detours.h"

typedef _Return_type_success_(return >= 0) long NTSTATUS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

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
	);
NTSTATUS NTAPI NtQueryDirectoryFileH(
	_In_ HANDLE FileHandle,	_In_opt_ HANDLE Event, _In_opt_ PVOID ApcRoutine, _In_opt_ PVOID ApcContext, _Out_ PVOID IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ BOOLEAN ReturnSingleEntry, _In_opt_ PUNICODE_STRING FileName, _In_ BOOLEAN RestartScan
);

namespace vec {
	class FVector {
		struct Entry {
			size_t Size;
			byte   Data[];
		};

	public:
		FVector();
		~FVector();

		void* AllocateObject(_In_ size_t nSize);
		void FreeObject(_In_ void* p);

		void* GetFirstEntry();
		void* GetNextEntry(_In_ void* p);

	private:
		status ResizeVector(_In_ size_t nSize);

		void* m_Vec;       // Address of Vector
		size_t m_Used = 0; // Size in bytes Used (this allso describes the current offset as there're no possible caves,
						   // everything is contiguous and will be compacted as soon as possible)
		size_t m_Size;     // Size of Table that is commited
	};

	class OptiVec : public FVector {
	public:
		OptiVec();
		~OptiVec();

		void* AllocateObject(_In_ size_t nSize);
		void FreeObject(_In_ void* p);

		void* operator[](_In_ uint32 i);

		uint16 GetItemCount();
		void LockVector();
		void UnlockVector();

	private:
		void** m_RefTable = nullptr;
		uint16 m_Count = 0;
		bool m_Modified = true;
		CRITICAL_SECTION m_cs;
	};
}