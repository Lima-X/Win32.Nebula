// This Project is used to code and debug modules outside of the actual riftProject itself
#include "..\..\global\global.h"
#include <malloc.h>

// Rules for this class:
// 1. Internaly refers to an entry as the listentry itself, outside of this class data is refered to as the data following its entry
// 2. the physical data uses relative addresses or relatives offsets, the class converts thes ra/ro's to expose them outside as addresses
// 3. the internals refer always to the whole while the outside access is limited to the object

// This Doubly-Linked List only supports a maximum size of 2^16 - 16byte head
// the data itself uses 16bit addressing itself that gets internaly converted to usable VA's
class DlList {
	typedef unsigned short size_t;
	struct ListEntry {
		word   prev; // relative address to previous entry (relative to BaseAddress)
		word   next; // RA to next entry
		size_t size; // sizeof data
	};

public:
	DlList(
		void* pBase,
		size_t nSize
	)
		: m_BaseAddress((ptr)pBase),
		m_nCapacity(nSize),
		m_nCapacityUsed(NULL)
	{
		memset((void*)m_BaseAddress, NULL, 0x4);
		dbg::TracePoint("dl-list constructed at: 0x%08x\n", pBase);
	}

	void* AddObject(void* pData, size_t nData) {
		void* pRet = nullptr;

		if (m_FirstEntry()) {
			ListEntry* prev, * next;
			ListEntry* entry = FindCave(nData + sizeof(ListEntry), prev, next);
			if (!entry)
				return nullptr; // Not enough space found

			InsertEntry(entry, prev, next);
			if (!prev || !next)
				!prev ? m_FirstEntry(entry) : m_LastEntry(entry);

			entry->size = nData;
			void* mem = (void*)((ptr)entry + sizeof(ListEntry));
			memcpy(mem, pData, nData);
			pRet = mem;
		}
		else { // Special Handler to Add first entry (and initialze list) ((possibly use a trampoline for this in the future))
			ListEntry* le = (ListEntry*)(m_BaseAddress + 0x10);
			*le = { NULL, NULL, (word)nData };
			memcpy((void*)((ptr)le + sizeof(ListEntry)), pData, nData);
			m_FirstEntry(le), m_LastEntry(le);
			pRet = (void*)((ptr)le + sizeof(ListEntry));
		}

		m_nCapacityUsed += nData + sizeof(ListEntry);
		// dbg::TracePoint("Object Added to list at: 0x%08x,\n                 offset: 0x%04x\n", (ptr)pRet, (ptr)pRet - m_BaseAddress);
		return pRet;
	}

	// This needs to be expanded, removal of objects mostly works, cleaning the entries is still buggy
	void RemoveObject(void* pAddr) {
		ListEntry* entry = (ListEntry*)((ptr)pAddr - sizeof(ListEntry));
		dbg::TracePoint("Removing Object Entry at: 0x%08x\n", entry);

		if (entry->size) { // Make sure entry is valid
			if (entry->next && entry->prev) {
				// Fix up links (link previous and next entry to each other)
				((ListEntry*)(entry->prev + m_BaseAddress))->next = entry->next;
				((ListEntry*)(entry->next + m_BaseAddress))->prev = entry->prev;
			}
			else { // Special Handling incase it is first or last entry
				if (entry->next) { // Remove First
					((ListEntry*)(entry->next + m_BaseAddress))->prev = NULL;
					m_FirstEntry((ListEntry*)(entry->next + m_BaseAddress));
				}
				else if (entry->prev) { // Remove Last
					((ListEntry*)(entry->prev + m_BaseAddress))->next = NULL;
					m_LastEntry((ListEntry*)(entry->prev + m_BaseAddress));
				}
				else { // Remove single entry
					m_FirstEntry(nullptr), m_LastEntry(nullptr);
				}
			}

			m_nCapacityUsed -= entry->size + sizeof(ListEntry);
			memset(entry, 0xcc, entry->size + sizeof(ListEntry));
			// entry->size = NULL;
		}
	}

private:
	void InsertEntry(
		_In_ ListEntry* entry,
		_In_ ListEntry* prev,
		_In_ ListEntry* next
	) {
		// Link entry into list
		if (prev) {
			prev->next = (ptr)entry - m_BaseAddress;
			entry->prev = (ptr)prev - m_BaseAddress;
		}
		else
			entry->prev = NULL;
		if (next) {
			next->prev = (ptr)entry - m_BaseAddress;
			entry->next = (ptr)next - m_BaseAddress;
		}
		else
			entry->next = NULL;
	}

	// finds space infornt the first, between the first and last and after the last entry
	// This will try to always find space at the lowest address possible
	ListEntry* FindCave(
		_In_  size_t      nSize,
		_Out_ ListEntry*& prev,
		_Out_ ListEntry*& next
	) {
		// Check for space before the current first entry // this currently fails
		if ((ptr)m_FirstEntry() - (m_BaseAddress + 0x10) >= nSize) {
			prev = nullptr, next = m_FirstEntry();
			return (ListEntry*)(m_BaseAddress + 0x10);
		}

		ListEntry* entry = m_FirstEntry();
		while (entry != m_LastEntry()) {
			if ((entry->next - (word)((ptr)entry - m_BaseAddress)) - (entry->size + sizeof(ListEntry)) >= nSize) {
				prev = entry, next = (ListEntry*)((ptr)entry->next + m_BaseAddress);
				return (ListEntry*)((ptr)entry + (entry->size + sizeof(ListEntry)));
			}
			else
				entry = (ListEntry*)(entry->next + m_BaseAddress);
		}

		// Check for space after the current last entry
		if ((m_BaseAddress + m_nCapacity) - (ptr)m_LastEntry() >= nSize) {
			prev = m_LastEntry(), next = nullptr;
			return (ListEntry*)((ptr)m_LastEntry() + (m_LastEntry()->size + sizeof(ListEntry)));
		}

		return nullptr;
	}

	inline ListEntry* m_FirstEntry() {
		return (ListEntry*)(*(word*)m_BaseAddress ? (void*)((*(word*)(m_BaseAddress + 0)) + m_BaseAddress) : nullptr);
	}
	inline void m_FirstEntry(_In_opt_ ListEntry* le) {
		*(word*)(m_BaseAddress + 0) = le ? (word)((ptr)le - m_BaseAddress) : (word)NULL;
	}
	inline ListEntry* m_LastEntry() {
		return (ListEntry*)(*(word*)m_BaseAddress ? (void*)((*(word*)(m_BaseAddress + 2)) + m_BaseAddress) : nullptr);
	}
	inline void m_LastEntry(_In_opt_ ListEntry* le) {
		*(word*)(m_BaseAddress + 2) = le ? (word)((ptr)le - m_BaseAddress) : (word)NULL;
	}

	const ptr    m_BaseAddress;   // BaseAddress that points to the internal offset 0x00
	const size_t m_nCapacity;     // Maximum size of data this container can hold in bytes
	size_t m_nCapacityUsed; // count of bytes currently used in the container
};

int main() {
	void* list_memory = malloc(0xffff);

	dbg::Benchmark bm(dbg::Benchmark::resolution::NANO);
	bm.Begin();
	DlList list(list_memory, 0xffff);

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
	char e[] = "this is  abit longer than before";
	liste[1] = (char*)list.AddObject(e, sizeof(e));

	list.RemoveObject(liste[0]);
	char f[] = "Hello test2";
	liste[0] = (char*)list.AddObject(f, sizeof(f));

	list.RemoveObject(liste[1]);
	list.RemoveObject(liste[0]);
	list.RemoveObject(liste[2]);

	uint32 dw = bm.End();
	return 0;
}
