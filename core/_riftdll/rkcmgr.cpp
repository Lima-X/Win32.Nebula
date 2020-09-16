// RootKit Control Manager
// This File is responsible for hosting a "server" that the rootkit-module can connect to.
// it will manage the information presented to the rootkit module as an unordered and unsorted
// table of entrys through a doubly-linked list
#include "_riftdll.h"

class DlList {
	struct ListEntry {
		word nlink; // offset to next entry
		word plink; // offset to last entry
		word nSize; // size of entry + entry header itself
	};

public:
	DlList(
		_In_ void*  pBaseAddress,
		_In_ size_t nTableSize
	)
		: m_BaseAddress(pBaseAddress),
		m_nListSize(nTableSize)
	{

	}

	status AddEntry(
		_In_ void* pData,
		_In_ word  nData
	) {

	}
	status RemoveEntry(
		_In_ void* addr
	) {

	}

private:
	const void*  m_BaseAddress;
	const size_t m_nListSize;
};


class IPC {

public:
	IPC() {

	}

private:

};