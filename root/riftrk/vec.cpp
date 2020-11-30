#include "riftrk.h"

namespace vec {
	// HVector (Handle Vector) is a stl like vector/array,
	// that uses handles to refer to an object instead,
	// allowing for fast traversel (which is needed for the hooks,
	// inorder to not slowdown the api'S as much as possible).
	// Each Hook will get its own (set of) Vector(s),
	// the vectors will be managed by the IO Procedure
	AnyVector::AnyVector()
		: m_Vec(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)),
		m_Size(0x1000) {
	#if _DEBUG
		memset(m_Vec, 0xcc, m_Size);
	#endif
	}
	AnyVector::~AnyVector() {
		VirtualFree(m_Vec, 0, MEM_RELEASE);
	}

	void* AnyVector::AllocateObject( // Returns a Pointer to the allocated space (valid only for limited time, see FreeObject)
		_In_ size_t nSize          // The size of the Entry to be allocated
	) {
		if (nSize + sizeof(Entry) > m_Size - m_Used)
			if (ResizeVector(m_Used + (nSize + sizeof(Entry))))
				return nullptr; // Failed to resize

		void* mem = (void*)(m_Used + (ptr)m_Vec);
		m_Used += ((Entry*)mem)->Size = nSize + sizeof(Entry);
		m_Count++;
		return (void*)((ptr)mem + sizeof(Entry));
	}
	void AnyVector::FreeObject( // Frees/Deallocates a Entry (a call will invalidate all pointers returned by Allocate Object)
		_In_ void* p          // The Entry to be freed
	) {
		Entry* mem = (Entry*)((ptr)p - sizeof(Entry));
		size_t nmem = mem->Size;
		memmove(mem, (void*)((ptr)mem + mem->Size),
			m_Used - (((ptr)mem + mem->Size) - (ptr)m_Vec));
		m_Used -= nmem;
		if (m_Used / 0x1000 < m_Size / 0x1000)
			ResizeVector(m_Used);
		m_Count--;
	}

	void* AnyVector::GetFirstEntry() { // Gets the First Entry in the Vector
		return (void*)((ptr)m_Vec + sizeof(Entry));
	}
	void* AnyVector::GetNextEntry( // Gets the next relative entry
		_In_ void* p             // Relative Entry
	) {
		Entry* mem = (Entry*)((ptr)p - sizeof(Entry));
		if ((((ptr)mem + mem->Size) - (ptr)m_Vec) < m_Used)
			return (void*)(((ptr)mem + mem->Size) + sizeof(Entry));
		return nullptr;
	}

	status AnyVector::ResizeVector( // Grows or Shrinks the Vector
		_In_ size_t nSize         // Size of new Vector, will be rounded to page size
	) {
		void* mem = VirtualAlloc(nullptr, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (mem) {
			memcpy(mem, m_Vec, m_Used);
			VirtualFree(m_Vec, 0, MEM_RELEASE);
			m_Vec = mem;
			m_Size = RoundUpToMulOfPow2(nSize, 0x1000);
		} else
			return -1; // Error reallocating Memory
		return 0;
	}

	uint32 AnyVector::GetItemCount() {
		return m_Count;
	}
	void AnyVector::ReadLock() {
		AcquireSRWLockShared(&m_srw);
	}
	void AnyVector::ReadUnlock() {
		ReleaseSRWLockShared(&m_srw);
	}
	void AnyVector::WriteLock() {
		AcquireSRWLockExclusive(&m_srw);
	}
	void AnyVector::WriteUnlock() {
		ReleaseSRWLockExclusive(&m_srw);
	}
}
