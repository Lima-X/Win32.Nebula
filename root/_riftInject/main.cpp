#include "_riftInject.h"

class InjectorMgr {
	struct Process;

public:
	InjectorMgr()
		: m_nReserved(16), m_nCommited(0)
	{
		m_Heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0x1000 * sizeof(Process));
		if (!m_Heap)
			return; // unlikely to happen (near impossible), but just in case...

		m_procList = (Process*)HeapAlloc(m_Heap, HEAP_NO_SERIALIZE, 0x10 * sizeof(Process));
	}
	~InjectorMgr() {
		HeapFree(m_Heap, HEAP_NO_SERIALIZE, m_procList);
		HeapDestroy(m_Heap);
	}

	status EnumerateProcesses() {
		// Set all Entries to not Running (this will be important as we will set them back to running if they do,
		// if not they will be removed from the list (, this is basically important only for the Injector))
		for (ushort i = 0; i < m_nCommited; i++)
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
					for (ushort i = 0; i < m_nCommited; i++)
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
				return -2; // Couldn't enumerate/evaluate the Snapshot, yes this cause a memory leak... Too bad.

			free(pe32);
			CloseHandle(hProcSnap);
		}

		// Cleanup the Processlist (unreference them)
		for (ushort i = 0; i < m_nCommited; i++) {
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
	ushort m_nCommited;     // The number of elements currently in the list ("commited")
	ushort m_nReserved;     // The number of elements currently allocated but free to use ("reserved")

	status IAddProcess(const DWORD dwPid) {
		if (m_nReserved <= m_nCommited)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved += 4) * sizeof(Process));

		m_procList[m_nCommited].dwPid = dwPid;
		m_procList[m_nCommited].bRunning = true;
		m_nCommited++;

		// call injector here
		// blackbone::MMap::MapImage()

		return 0;
	}
	status IRemoveProcess(const ushort nIndex) {
		for (ushort i = nIndex; i < m_nCommited - 1; i++)
			m_procList[i] = m_procList[i + 1];
		m_nCommited--;

		if (m_nReserved - m_nCommited >= 4)
			HeapReAlloc(m_Heap, HEAP_NO_SERIALIZE, m_procList, (m_nReserved -= 4) * sizeof(Process));
		return 0;
	}
};

int WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     int       nCmdShow
) {
	InjectorMgr imgr;




	return 0;
}