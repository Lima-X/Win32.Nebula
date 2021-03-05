// Nebula Core - self protecting "nano" kernel
#pragma once

#include "nbp.h"

#pragma region Protected Sections
// #pragma warning(disable : 4330)

// Protected Data-Section
#pragma section(N_PSRW1, read, write)
#pragma section(N_PSRW2, read, write)

// Merge protected sections
#pragma comment(linker, "/merge:.nbrw1=.nb1")
#pragma comment(linker, "/merge:.nbrw2=.nb2")

// Merge loader code into a loader section
#pragma comment(linker, "/merge:.text=.nb0")
#pragma comment(linker, "/merge:.data=.nb0")
#pragma comment(linker, "/merge:.rdata=.nb0")

// Declaration Protection Specification
#define N_PROTECTEDD ALLOC_DATA(N_PSRW1)
#define N_PROTECTEDX ALLOC_CODE(N_PS1)
#pragma endregion


namespace ldr {
	LIST_ENTRY* GetModuleList();
	#undef SearchPath
	status GetSystemDllbyHash(_In_ wchar* SearchPath, _In_ u64 Hash, _Out_ wchar* Path);
	void*  ImportFunctionByHash(_In_ handle Module, _In_ u64 Hash);
	handle GetModuleHandleByHash(_In_ u64 Hash);
	status ApplyBaseRelocationsOnSection(_In_ handle Module, _In_ IMAGE_SECTION_HEADER* Section, _In_opt_ void* Address, _In_ i64 RelocationDelta);
}

status ValidateImportAddressTable(_In_ handle Module);
poly CodePointer(_In_ poly x);
#define EncodePointer(ptr) (handle)CodePointer((poly)(ptr))
#define DecodePointer(ptr) (void*)CodePointer((poly)(ptr))

namespace utl {
	status GenerateSessionId(_Out_ u64& SessionId);
	status GenerateHardwareId(_Out_ u64& HardwareId);
}

class svc2 {
	typedef poly(__x64call* ServiceFunctionPointer)(poly FunctionContext);
	struct FunctionDispatchEntry {
		handle                 ModuleAssociation;
		u64                    FunctionId;
		ServiceFunctionPointer FunctionPointer;
	};

public:
	 svc2();
	~svc2();

	status RegisterServiceFunction(_In_ u64 FunctionId, _In_ ServiceFunctionPointer FunctionPointer);
	status ServiceCall(_In_ u64 ServiceId, _Out_ poly* ReturnValue, _In_opt_ poly ServiceParameters);

private:
	status SearchListForEntry(_In_ u64 ServiceId, _Out_ FunctionDispatchEntry*& FunctionEntry);

	handle m_DispatchTable; // Function-Dispatch-Table (HeapList storing the Services)
};
inline svc2* ServiceManager;

class DoublyLinkedList {           // Doubly Linked list that supports object allocation and object referencing
	struct ListEntry {             // Nodeobject allcoated and linked into the list
		ListEntry* NextEntry;      // A Pointerpair to tne next and previous entry in the list
		ListEntry* PreviousEntry;

		union {                   // this field contains either
			void* VirtualAddress; // The Address of the Buffer that stores the actual data
			i64   EntrySize;      // The size of the Object (if non reference object signbit is set)
		} Misc;
	};

public:
	// Constructors
	DoublyLinkedList(_In_ handle Heap);

	// Allocators
	handle AllocateObject(_In_ size_t ObjectSize);
	handle ReferenceObject(_In_ void* VirtualAddress);
	void   DestroyObject(_In_ handle Object);

	// Information translators
	void*  GetObjectAddress(_In_ handle Object);
	size_t GetObjectSize(_In_ handle Object);

	// Enumerators
	handle GetFirstObject();
	handle GetLastObject();
	handle GetNextObject(_In_ handle Object);
	handle GetPreviousObject(_In_ handle Object);

	void LockListExclusive();
	void LockListShared();
	void UnlockList();

private:
	ListEntry* AllocateEntryInternal(_In_ size_t ObjectSize);

	const handle m_MemoryContainer;            // The heap used to allocate elements

	struct _ListLock {
		SRWLOCK  SrwLockInternal;              // The internal SRWLOCK
		u32      OwningThread;                 // The Thread that owns the exclusive lock
		struct {
			u32  ExclusiveRecursionCount : 28; // The count of times the owning thread owns this lock
			u32  ExclusiveModeEnabled    :  1; // Marks if the Lock is in exclusive mode
		};
	}            m_ListLock;

	ListEntry*   m_FirstEntry;                 // A pointerpair pointing ot the first and last entry in the list
	ListEntry*   m_LastEntry;
};



// Global Managment Information
// has to be named because of a stupid compiler bug lol, bug report at:
// https://developercommunity.visualstudio.com/content/problem/1312147/c17-global-unnamed-inline-struct-may-not-be-the-sa.html
// Apparently its not a compilerbug, however i do not aggree with the way this is handled and this really doesnt seem to be
// Standard conform.
struct _NebulaInternalGlobalData {
	handle ModuleBase;

	u64 ProcessCookie;
	u8  CookieOffset;

	u64 HardwareId;
	u64 SessionId;

	handle NebulaHeap; // Encoded with CodePointer
} volatile inline g_;
