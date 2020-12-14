#include "rk.h"

namespace dt {
	class ThreadUpdate {
	public:
		ThreadUpdate() {
			void* mem;

			size_t nmem = 0;
			while (1) {
				mem = VirtualAlloc(nullptr, nmem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				NTSTATUS s = hk::NtQuerySystemInformation(0x05, mem, nmem, (dword*)&nmem);
				if (!s)
					break;
				VirtualFree(mem, 0, MEM_RELEASE);
			}

			m_NtDll::SYSTEM_PROCESS_INFORMATION* PEntry = (m_NtDll::SYSTEM_PROCESS_INFORMATION*)mem;
			u32 PId = GetCurrentProcessId();
			while (true) {
				if ((u32)PEntry->UniqueProcessId == PId) {
					m_NtDll::SYSTEM_THREAD_INFORMATION* TEntry = (m_NtDll::SYSTEM_THREAD_INFORMATION*)(PEntry + 1);

					m_ThreadCount = PEntry->NumberOfThreads;
					m_ThreadList = (HANDLE*)HeapAlloc(GetProcessHeap(), NULL, (m_ThreadCount - 1) * sizeof(*m_ThreadList));

					for (u32 i = 0; i < m_ThreadCount; i++) {
						u32 TId = (u32)TEntry->ClientId.UniqueThread;
						if (TId != GetCurrentThreadId()) // Ignore its own Thread
							m_ThreadList[i] = OpenThread(THREAD_SUSPEND_RESUME, false, TId);
						TEntry++;
					}

					break;
				}

				if (!PEntry->NextEntryOffset)
					break;
				PEntry = (m_NtDll::SYSTEM_PROCESS_INFORMATION*)((ptr)PEntry->NextEntryOffset + (ptr)PEntry);
			}

			VirtualFree(mem, 0, MEM_RELEASE);
		}
		~ThreadUpdate() {
			for (u32 i = 0; i < m_ThreadCount; i++)
				CloseHandle(m_ThreadList[i]);
		}

		void SuspendThreads() {
			for (u32 i = 0; i < m_ThreadCount; i++)
				SuspendThread(m_ThreadList[i]);
		}
		void ResumeThreads() {
			for (u32 i = 0; i < m_ThreadCount; i++)
				ResumeThread(m_ThreadList[i]);
		}

	private:
		u32     m_ThreadCount = 0;
		HANDLE* m_ThreadList;

	};

	class TrampolineMgr {
		struct TrampolinePage {
			void* BaseAddress;    // The BaseAddress/Location of the Page Used for the Trampolines
			qword AllocationMask; // A Mask that describes which 64b Blocks in the Page are Used
		};

	public:
		struct SyscallTrampolineX64 {
			// Thunk to Hook
			byte ToDetour[4 + 8];
			// First 2 Instructions (8b) of Target followed by an absolute jump to the rest of the Target
			byte TargetThunk[8 + (4 + 8)];
		};

		void* AllocateUsablePageWithinReach(
			_In_ void* pTarget
		) {
			for (ptr i = (ptr)pTarget; (i + sizeof(SyscallTrampolineX64)) - (ptr)pTarget < 0x7fffffff; i += 4096) {
				// Get PageInformation and Check if Page is Usable
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery((void*)i, &mbi, sizeof(mbi));
				if (mbi.State == MEM_FREE) {
					void* mem = VirtualAlloc(mbi.BaseAddress, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (!mem)
						continue;

					return mem;
				}
			}

			return nullptr;
		}
		SyscallTrampolineX64* AlloctateTrampolineWithinReach(
			_In_ void* pTarget
		) {
			// Go through allocated TrampolineList first and check if code is withing region,
			// if so use that trampoline instead, if no trampoline has been allocated yet
			// or no trampoline is within 2gb reach allocate a new one


		newalloc: // Allocate a new TrampolinePage
			void* mem = AllocateUsablePageWithinReach(pTarget);
			if (!mem)
				return nullptr; // Couldn't Allocate Page

			// Add Entry to the List of existing Trampoline Pages
			if (m_TPArray)
				m_TPArray = (TrampolinePage*)HeapReAlloc(GetProcessHeap(), NULL, m_TPArray, m_TPSize += sizeof(TrampolinePage));
			else
				m_TPArray = (TrampolinePage*)HeapAlloc(GetProcessHeap(), NULL, m_TPSize += sizeof(TrampolinePage));

			TrampolinePage* Page = m_TPArray + (m_TPSize / sizeof(*m_TPArray) - 1);
			Page->BaseAddress = mem;
			Page->AllocationMask = (qword)1 << 63;

			return (SyscallTrampolineX64*)Page->BaseAddress;
		}

	private:
		TrampolinePage* m_TPArray = nullptr;
		size_t          m_TPSize = 0;
	};
	TrampolineMgr tmgr;

	void GenerateAbsoluteJump( // Generates a 12byte Absolute jump
		_In_ void* pCode,      // Address at which to generate jumpcode
		_In_ ptr   Address     // Address to jump to
	) {
		*((word*&)pCode)++ = 0xb848;
		*((qword*&)pCode)++ = Address;
		*(word*&)pCode = 0xe0ff;
	}
	void GenerateIntermediateRelativeJump( // Generates a 5byte relative jump (jump address has to be withing reach of 2gb)
		_In_ void* pCode,                  // The Address at where to generate the Code
		_In_ ptr   Address                 // The Address to Jump to (this has to be within 2gb of the pCode)
	) {
		ptr Offset = (ptr)pCode + 5;        // Relative Offset
		*((byte*&)pCode)++ = 0xe9;          // jmp +imm32
		*(dword*&)pCode = Address - Offset; // Relative jump Address
	}

	status DetourSyscallStub(
		_In_ void** ppTarget,
		_In_ void* pHook
	) {
		void* pTarget = *ppTarget;
		auto Trampoline = tmgr.AlloctateTrampolineWithinReach(pTarget);

		// Generate Bidirectional Trampoline (Thunk)
		GenerateAbsoluteJump(&Trampoline->ToDetour, (ptr)pHook);
		__movsb((byte*)&Trampoline->TargetThunk, (byte*)pTarget, 8);
		GenerateAbsoluteJump((void*)((ptr)&Trampoline->TargetThunk + 8), (ptr)pTarget + 8);
		FlushInstructionCache(GetCurrentProcess(), Trampoline, sizeof(*Trampoline));

		// Start Transaction
		ThreadUpdate tu;
		tu.SuspendThreads();

		// Detour Targetfuction to Hook
		dword Protect;
		VirtualProtect(pTarget, 8, PAGE_EXECUTE_READWRITE, &Protect);
		GenerateIntermediateRelativeJump(pTarget, (ptr)&Trampoline->ToDetour);
		__stosb((byte*)((ptr)pTarget + 5), 0xcc, 3); // Pad the unused 3 bytes with breakpoints
		VirtualProtect(pTarget, 8, Protect, &Protect);
		FlushInstructionCache(GetCurrentProcess(), pTarget, 8);

		// Set Detoured funtion to Trampoline Jumper
		*ppTarget = &Trampoline->TargetThunk;
		tu.ResumeThreads();
		return 0;
	}
}