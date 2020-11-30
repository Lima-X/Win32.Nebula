#include "riftrk.h"

namespace dt {
	class ThreadUpdate {
	public:
		ThreadUpdate() {
			void* mem;

			while (1) {
				size_t nmem = 0;
				mem = VirtualAlloc(nullptr, nmem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				NTSTATUS s = hk::NtQuerySystemInformation(0x05, mem, nmem, (ulong*)&nmem);
				if (!s)
					break;
				VirtualFree(mem, 0, MEM_RELEASE);
			}

			nt::SYSTEM_PROCESS_INFORMATION* PEntry = (nt::SYSTEM_PROCESS_INFORMATION*)mem;
			uint32 PId = GetCurrentProcessId();
			while (true) {
				if ((uint32)PEntry->UniqueProcessId == PId) {
					nt::SYSTEM_THREAD_INFORMATION* TEntry = (nt::SYSTEM_THREAD_INFORMATION*)(PEntry + 1);

					m_ThreadCount = PEntry->NumberOfThreads;
					m_ThreadList = (HANDLE*)HeapAlloc(GetProcessHeap(), NULL, (m_ThreadCount - 1) * sizeof(*m_ThreadList));

					for (uint32 i = 0; i < m_ThreadCount; i++) {
						uint32 TId = (uint32)TEntry->ClientId.UniqueThread;
						if (TId != GetCurrentThreadId()) // Ignore its own Thread
							m_ThreadList[i] = OpenThread(THREAD_SUSPEND_RESUME, false, TId);
						TEntry++;
					}
				}

				if (!PEntry->NextEntryOffset)
					break;
				PEntry = (nt::SYSTEM_PROCESS_INFORMATION*)((ptr)PEntry->NextEntryOffset + (ptr)PEntry);
			}

			VirtualFree(mem, 0, MEM_RELEASE);
		}
		~ThreadUpdate() {
			for (uint32 i = 0; i < m_ThreadCount; i++)
				CloseHandle(m_ThreadList[i]);
		}

		void SuspendThreads() {
			for (uint32 i = 0; i < m_ThreadCount; i++)
				SuspendThread(m_ThreadList[i]);
		}
		void ResumeThreads() {
			for (uint32 i = 0; i < m_ThreadCount; i++)
				ResumeThread(m_ThreadList[i]);
		}

	private:
		uint32  m_ThreadCount = 0;
		HANDLE* m_ThreadList;

	};

	class TrampolineMgr {
		struct TrampolinePage {
			void* BaseAddress;    // The BaseAddress/Location of the Page Used for the Trampolines
			ulong64 AllocationMask; // A Mask that describes which 64b Blocks in the Page are Used
		};

	public:
		struct SyscallTrampolineX64 {
			struct ToDetour {
				byte  JumpAbsoluteIndirect[6];
				void* HookAddress;
			} Detour;
			struct RealTarget {
				byte  JumpAbsoluteIndirect[8 + 6]; // First 2 Instructions of syscall stub + Indirect Absolute Jump
				void* PatchedAddress;
			} RealTarget;
		};

		void* FindUsablePageWithinReach(
			_In_ void* pTarget
		) {
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(pTarget, &mbi, sizeof(mbi));
			ptr StartingAddress = (ptr)mbi.AllocationBase + mbi.RegionSize;

			for (ptr i = StartingAddress; (i + sizeof(SyscallTrampolineX64)) - (ptr)pTarget < 0x7fffffff; i += 4096) {
				// Get PageInformation and Check if Page is Usable
				VirtualQuery((void*)i, &mbi, sizeof(mbi));
				if (mbi.State == MEM_FREE)
					return mbi.BaseAddress;
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
			void* mem = FindUsablePageWithinReach(pTarget);
			mem = VirtualAlloc(mem, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!mem)
				return nullptr; // Couldn't Allocate Page

			// Add Entry to the List of existing Trampoline Pages
			if (m_TPArray)
				m_TPArray = (TrampolinePage*)realloc(m_TPArray, m_TPSize += sizeof(TrampolinePage));
			else
				m_TPArray = (TrampolinePage*)malloc(m_TPSize += sizeof(TrampolinePage));

			TrampolinePage* Page = m_TPArray + (m_TPSize / sizeof(*m_TPArray) - 1);
			Page->BaseAddress = mem;
			Page->AllocationMask = (ulong64)1 << 63;

			return (SyscallTrampolineX64*)Page->BaseAddress;
		}

	private:
		TrampolinePage* m_TPArray = nullptr;
		size_t          m_TPSize = 0;
	};
	TrampolineMgr tmgr;

	void GenerateAbsoluteJump(               // Generates a 12byte Absolute jump
		_In_ void* pTrampolineCode,
		_In_ ptr*  pTrampolineIndirectMember
	) {
		*((word*&)pTrampolineCode)++ = 0x25ff;                                                // jmp [rip
		*(dword*)pTrampolineCode = (ptr)pTrampolineIndirectMember - (ptr)pTrampolineCode + 6; // + offset]
	}
	void GenerateIntermediateRelativeJump( // Generates a 5byte relative jump (jump address has to be withing reach of 2gb)
		_In_ void* pCode,                 // The Address at where to generate the Code
		_In_ void* pTargetAddress
	) {
		*((byte*&)pCode)++ = 0xe9; // jmp +imm32
		*((dword*&)pCode)++ = (ptr)pTargetAddress - ((ptr)pCode + 5);
	}

	status DetourSyscallStub(
		_In_ void** ppTarget,
		_In_ void* pHook
	) {
		void* pTarget = *ppTarget;
		auto Trampoline = tmgr.AlloctateTrampolineWithinReach(pTarget);

		// Setup Detour Thunk
		GenerateAbsoluteJump(&Trampoline->Detour.JumpAbsoluteIndirect, (ptr*)&Trampoline->Detour.HookAddress);
		Trampoline->Detour.HookAddress = pTarget;

		// Setup Trampoline to Original function
		// Copy First 2 Instructions of Syscallstub and generate Jump
		memcpy(&Trampoline->RealTarget.JumpAbsoluteIndirect, pTarget, 8);
		GenerateAbsoluteJump((void*)((ptr)&Trampoline->RealTarget.JumpAbsoluteIndirect + 8),
			(ptr*)&Trampoline->RealTarget.PatchedAddress);
		*(qword*)((ptr)pTarget + 8) = (ptr)pTarget + 8;
		FlushInstructionCache(GetCurrentProcess(), Trampoline, sizeof(*Trampoline));

		// Start Transaction
		ThreadUpdate tu;
		tu.SuspendThreads();

		// Detour Targetfuction to Detourhook
		GenerateIntermediateRelativeJump(pTarget, &Trampoline->Detour.JumpAbsoluteIndirect);
		memset((void*)((ptr)pTarget + 5), 0xcc, 3); // Pad the unused 3 bytes with breakpoints
		FlushInstructionCache(GetCurrentProcess(), pTarget, 8);

		// Set Detoured funtion to Trampoline Jumper
		*ppTarget = &Trampoline->RealTarget.JumpAbsoluteIndirect;

		tu.ResumeThreads();

		return 0;
	}
}