#include "riftrk.h"

namespace vec {
	// HVector (Handle Vector) is a stl like vector/array,
	// that uses handles to refer to an object instead,
	// allowing for fast traversel (which is needed for the hooks,
	// inorder to not slowdown the api'S as much as possible).
	// Each Hook will get its own (set of) Vector(s),
	// the vectors will be managed by the IO Procedure
	FVector::FVector()
		: m_Vec(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)),
		m_Size(0x1000) {
	#if _DEBUG
		memset(m_Vec, 0xcc, m_Size);
	#endif
	}
	FVector::~FVector() {
		VirtualFree(m_Vec, 0, MEM_RELEASE);
	}

	void* FVector::AllocateObject( // Returns a Pointer to the allocated space (valid only for limited time, see FreeObject)
		_In_ size_t nSize          // The size of the Entry to be allocated
	) {
		if (nSize + sizeof(Entry) > m_Size - m_Used)
			if (ResizeVector(m_Used + (nSize + sizeof(Entry))))
				return nullptr; // Failed to resize

		void* mem = (void*)(m_Used + (ptr)m_Vec);
		m_Used += ((Entry*)mem)->Size = nSize + sizeof(Entry);
		return (void*)((ptr)mem + sizeof(Entry));
	}
	void FVector::FreeObject( // Frees/Deallocates a Entry (a call will invalidate all pointers returned by Allocate Object)
		_In_ void* p          // The Entry to be freed
	) {
		Entry* mem = (Entry*)((ptr)p - sizeof(Entry));
		size_t nmem = mem->Size;
		memmove(mem, (void*)((ptr)mem + mem->Size),
			m_Used - (((ptr)mem + mem->Size) - (ptr)m_Vec));
		m_Used -= nmem;
		if (RoundUpToMulOfPow2(m_Used, 0x1000) < m_Size)
			ResizeVector(m_Used);
	}

	void* FVector::GetFirstEntry() { // Gets the First Entry in the Vector
		return (void*)((ptr)m_Vec + sizeof(Entry));
	}
	void* FVector::GetNextEntry( // Gets the next relative entry
		_In_ void* p             // Relative Entry
	) {
		Entry* mem = (Entry*)((ptr)p - sizeof(Entry));
		if ((((ptr)mem + mem->Size) - (ptr)m_Vec) < m_Used)
			return (void*)(((ptr)mem + mem->Size) + sizeof(Entry));
		return nullptr;
	}

	status FVector::ResizeVector( // Grows or Shrinks the Vector
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


	OptiVec::OptiVec() {
		InitializeCriticalSection(&m_cs);
	}
	OptiVec::~OptiVec() {
		if (m_RefTable)
			free(m_RefTable);
		DeleteCriticalSection(&m_cs);
	}

	void* OptiVec::AllocateObject(
		_In_ size_t nSize
	) {
		EnterCriticalSection(&m_cs);
		void* mem = FVector::AllocateObject(nSize);
		if (!mem)
			return nullptr;
		m_Count++;
		m_Modified = true;
		return mem;
		LeaveCriticalSection(&m_cs);
	}
	void OptiVec::FreeObject(
		_In_ void* p
	) {
		EnterCriticalSection(&m_cs);
		FVector::FreeObject(p);
		m_Count--;
		m_Modified = true;
		LeaveCriticalSection(&m_cs);
	}

	void* OptiVec::operator[](
		_In_ uint32 i
		) {
		if (m_Count && m_Modified) {
			EnterCriticalSection(&m_cs);
			if (m_RefTable)
				m_RefTable = (void**)realloc(m_RefTable, m_Count * sizeof(void*));
			else
				m_RefTable = (void**)malloc(m_Count * sizeof(void*));

			m_RefTable[0] = GetFirstEntry();
			for (int i = 1; i < m_Count; i++) {
				void* mem = GetNextEntry(m_RefTable[i - 1]);
				if (mem)
					m_RefTable[i] = mem;
			}

			m_Modified = false;
			LeaveCriticalSection(&m_cs);
		} else if (m_Modified) {
			free(m_RefTable);
			m_RefTable = nullptr;
			m_Modified = false;
		}

		void* ret = nullptr;
		if (i < m_Count)
			ret = m_RefTable[i];
		return ret;
	}

	uint16 OptiVec::GetItemCount() {
		return m_Count;
	}
	void OptiVec::LockVector() {
		EnterCriticalSection(&m_cs);
	}
	void OptiVec::UnlockVector() {
		LeaveCriticalSection(&m_cs);
	}
}

void SmartVecTest() {
	vec::OptiVec vec;

	int* a = (int*)vec.AllocateObject(4);
	*a = 556421;

	a = (int*)vec[0];

	long long* b = (long long*)vec.AllocateObject(8);
	*b = 55644567887426321;

	char* str = (char*)vec.AllocateObject(21);
	strcpy(str, "Hello this is a test");

	vec.FreeObject(b);
	vec.FreeObject(a);

	void* test = vec[0];

	int* c = (int*)vec.AllocateObject(20);
	*c = 554276421;

	c = (int*)vec.AllocateObject(20);
	*c = 554276421;

	int* d = (int*)vec.AllocateObject(0x1200);
	*d = 554276421;

	c = (int*)vec.AllocateObject(20);
	*c = 554276421;

	for (int i = 0; i < 10; i++) {
		void* mem = vec[0];
		if (mem)
			vec.FreeObject(mem);
		else
			break;
	}
}