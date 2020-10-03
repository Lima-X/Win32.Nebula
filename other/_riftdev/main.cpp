// This Project is used to code and debug modules outside of the actual riftProject itself
#include "global.h"
#include <malloc.h>

// Rules for this class:
// 1. Internaly refers to an entry as the listentry itself, outside of this class data is refered to as the data following its entry
// 2. the physical data uses relative addresses or relatives offsets, the class converts thes ra/ro's to expose them outside as addresses
// 3. the internals refer always to the whole while the outside access is limited to the object
// The data itself uses [template::T] addressing itself that gets internaly converted to usable VA's
template<
	typename T = dword, // default internal offset type: 32bit
	T Capacity = 0xffff // Max Capacity, default 64k
> class DlList {
	static constexpr size_t nHead = (sizeof(T) * 4);
	struct ListEntry {
		T prev; // relative address to previous entry (relative to BaseAddress)
		T next; // RA to next entry
		T size; // sizeof data
	};

public:
	DlList(         // Used to connect to the spcified
		void* pBase // Address of memoryblock
	)
		: m_BaseAddress((ptr)pBase) {}
	DlList(
		void* (*alloc)(size_t nSize) // memory allocation function
	)
		: m_BaseAddress((ptr)alloc(Capacity))
	{
		// memset((void*)m_BaseAddress, NULL, (sizeof(T) * 2));
		setEntry(Property::FirstEntry, nullptr),
			setEntry(Property::LastEntry, nullptr);
		const_cast<T&>(m_nCapacity) = Capacity - nHead;
		m_nCapacityUsed = 0;
		dbg::TracePoint("dl-list constructed at: %#08x\n", m_BaseAddress);
	}

	void* AddObject(
		_In_ void* pData,
		_In_ T     nData
	) {
		void* pRet = nullptr;

		if (getEntry(Property::FirstEntry)) {
			ListEntry* prev, * next;
			ListEntry* pEntry = FindCave(nData + sizeof(ListEntry), prev, next);
			if (!pEntry)
				return nullptr; // Not enough space found

			InsertEntry(pEntry, prev, next);
			if (!prev || !next)
				!prev ? setEntry(Property::FirstEntry, pEntry) : setEntry(Property::LastEntry, pEntry);

			pEntry->size = nData;
			void* mem = (void*)((ptr)pEntry + sizeof(ListEntry));
			memcpy(mem, pData, nData);
			pRet = mem;
		} else { // Special Handler to Add first entry (and initialze list) ((possibly use a trampoline for this in the future))
		         // Due to a possible underflow in the CaveFinder method this handler wouldnt be needed and could be removed,
		         // as the CaveFinder would still successfully find a valid area an would correctly initialize the header
			ListEntry* le = (ListEntry*)(m_BaseAddress + nHead);
			*le = { NULL, NULL, nData };
			memcpy((void*)((ptr)le + sizeof(ListEntry)), pData, nData);
			setEntry(Property::FirstEntry, le),
				setEntry(Property::LastEntry, le);
			pRet = (void*)((ptr)le + sizeof(ListEntry));
		}

		m_nCapacityUsed += nData + sizeof(ListEntry);
		dbg::TracePoint("Object Added to list at: %#08x,\n%17soffset: 0x%#04x\n", (ptr)pRet, "", (ptr)pRet - m_BaseAddress);
		return pRet;
	}

	// This needs to be expanded, removal of objects mostly works, cleaning the entries is still buggy
	void RemoveObject(
		_In_ void* pAddr
	) {
		ListEntry* pEntry = (ListEntry*)((ptr)pAddr - sizeof(ListEntry));
		dbg::TracePoint("Removing Object Entry at: 0x%08x\n", pEntry);

		if (pEntry->size) { // Make sure entry is valid
			if (pEntry->next && pEntry->prev) {
				// Fix up links (link previous and next entry to each other)
				((ListEntry*)(pEntry->prev + m_BaseAddress))->next = pEntry->next;
				((ListEntry*)(pEntry->next + m_BaseAddress))->prev = pEntry->prev;
			} else { // Special Handling incase it is first or last entry
				if (pEntry->next) { // Remove First
					((ListEntry*)(pEntry->next + m_BaseAddress))->prev = NULL;
					setEntry(Property::FirstEntry, (ListEntry*)(pEntry->next + m_BaseAddress));
				} else if (pEntry->prev) { // Remove Last
					((ListEntry*)(pEntry->prev + m_BaseAddress))->next = NULL;
					setEntry(Property::LastEntry, (ListEntry*)(pEntry->prev + m_BaseAddress));
				} else { // Remove last existing entry
					setEntry(Property::FirstEntry, nullptr),
						setEntry(Property::LastEntry, nullptr);
				}
			}

			m_nCapacityUsed -= pEntry->size + sizeof(ListEntry);
#if _DEBUG
			memset(pEntry, 0xcc, pEntry->size + sizeof(ListEntry));
#else
			entry->size = 0;
#endif
		}
	}

	void* GetFirstEntry() {
		return (void*)((ptr)getEntry(Property::FirstEntry) + sizeof(ListEntry));
	}
	void* GetLastEntry() {
		return (void*)((ptr)getEntry(Property::LastEntry) + sizeof(ListEntry));
	}
	void* GetPreviousEntry(_In_ void* addr) {
		ptr p = ((ListEntry*)((ptr)addr - sizeof(ListEntry)))->prev;
		if (p)
			return (void*)((ptr)(p + m_BaseAddress) + sizeof(ListEntry));
		return nullptr;
	}
	void* GetNextEntry(_In_ void* addr) {
		ptr p = ((ListEntry*)((ptr)addr - sizeof(ListEntry)))->next;
		if (p)
			return (void*)((ptr)(p + m_BaseAddress) + sizeof(ListEntry));
		return nullptr;
	}

private:
	void InsertEntry(
		_In_ ListEntry* pEntry,
		_In_ ListEntry* prev,
		_In_ ListEntry* next
	) {
		// Link entry into list
		if (prev) {
			prev->next = (ptr)pEntry - m_BaseAddress;
			pEntry->prev = (ptr)prev - m_BaseAddress;
		} else
			pEntry->prev = NULL;
		if (next) {
			next->prev = (ptr)pEntry - m_BaseAddress;
			pEntry->next = (ptr)next - m_BaseAddress;
		} else
			pEntry->next = NULL;
	}

	// finds space infornt the first, between the first and last and after the last entry
	// This will try to always find space at the lowest address possible
	ListEntry* FindCave(
		_In_  size_t      nSize,
		_Out_ ListEntry*& prev,
		_Out_ ListEntry*& next
	) {
		// Check for space before the current first entry // this currently fails
		if ((ptr)getEntry(Property::FirstEntry) - (m_BaseAddress + nHead) >= nSize) {
			prev = nullptr, next = getEntry(Property::FirstEntry);
			return (ListEntry*)(m_BaseAddress + nHead);
		}

		ListEntry* entry = getEntry(Property::FirstEntry);
		while (entry != getEntry(Property::LastEntry)) {
			if ((entry->next - (dword)((ptr)entry - m_BaseAddress)) - (entry->size + sizeof(ListEntry)) >= nSize) {
				prev = entry, next = (ListEntry*)((ptr)entry->next + m_BaseAddress);
				return (ListEntry*)((ptr)entry + (entry->size + sizeof(ListEntry)));
			} else
				entry = (ListEntry*)(entry->next + m_BaseAddress);
		}

		// Check for space after the current last entry
		if ((m_BaseAddress + m_nCapacity) - (ptr)getEntry(Property::LastEntry) >= nSize) {
			prev = getEntry(Property::LastEntry), next = nullptr;
			return (ListEntry*)((ptr)getEntry(Property::LastEntry) + (getEntry(Property::LastEntry)->size + sizeof(ListEntry)));
		}

		return nullptr;
	}

	enum Property {
		FirstEntry = sizeof(T) * 0,
		LastEntry  = sizeof(T) * 1
	};
	inline ListEntry* getEntry(
		_In_ Property atr
	) {
		if (atr <= Property::LastEntry)
			return *(T*)(m_BaseAddress + atr) ? (ListEntry*)((*(T*)(m_BaseAddress + atr)) + m_BaseAddress) : nullptr;
		return nullptr;
	}
	inline void setEntry(
		_In_     Property atr,
		_In_opt_ void*    addr
	) {
		if (atr <= Property::LastEntry)
			*(T*)(m_BaseAddress + atr) = addr ? (T)((ptr)addr - m_BaseAddress) : NULL;
	}

	const ptr m_BaseAddress;                                          // BaseAddress that points to the internal offset 0x00
	const T&  m_nCapacity     = *(T*)(m_BaseAddress + sizeof(T) * 2); // Maximum size of data this container can hold in bytes
		  T&  m_nCapacityUsed = *(T*)(m_BaseAddress + sizeof(T) * 3); // count of bytes currently used in the container
};

int main() {
	dbg::Benchmark bm(dbg::Benchmark::Resolution::MICRO);
	bm.Begin();

	auto pipalloc = [](size_t nSize) {
		void* mem = malloc(nSize);
		memset(mem, 0xcd, nSize);
		return mem;
	};
	DlList<byte> list(pipalloc);
	char* liste[10];

	char a[] = "Hello";
	liste[0] = (char*)list.AddObject(a, sizeof(a));
	char b[] = "HELLO YOU asshole";
	liste[1] = (char*)list.AddObject(b, sizeof(b));
	char c[] = "This is a Test";
	liste[2] = (char*)list.AddObject(c, sizeof(c));

	list.RemoveObject(liste[1]);
	char d[] = "this is smaller";
	liste[1] = (char*)list.AddObject(d, sizeof(d));
	list.RemoveObject(liste[1]);
	char e[] = "this is abit longer than before";
	liste[1] = (char*)list.AddObject(e, sizeof(e));

	list.RemoveObject(liste[0]);
	char f[] = "Hello test2";
	liste[0] = (char*)list.AddObject(f, sizeof(f));

	char* entry = (char*)list.GetFirstEntry();
	do {
		char* tentry = entry;
		entry = (char*)list.GetNextEntry(entry);
		list.RemoveObject(tentry);
	} while (entry);

	uint32 dw = bm.End();
	return 0;
}