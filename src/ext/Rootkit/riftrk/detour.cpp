#include "rk.h"

namespace dt {
	class ThreadUpdate {
	public:
		ThreadUpdate() {
			void* Memory;

			size_t nmem = 0;
			while (1) {
				Memory = VirtualAlloc(nullptr, nmem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				NTSTATUS s = hk::NtQuerySystemInformation(0x05, Memory, nmem, (dword*)&nmem);
				if (!s)
					break;
				VirtualFree(Memory, 0, MEM_RELEASE);
			}

			auto ProcessEntry = (SYSTEM_PROCESS_INFORMATION*)Memory;
			u32 PId = GetCurrentProcessId();
			while (true) {
				if ((u32)ProcessEntry->UniqueProcessId == PId) {
					auto ThreadEntry = (SYSTEM_THREAD_INFORMATION*)(ProcessEntry + 1);

					m_ThreadCount = ProcessEntry->NumberOfThreads;
					m_ThreadList = (handle*)HeapAlloc(GetProcessHeap(), NULL, (m_ThreadCount - 1) * sizeof(*m_ThreadList));

					for (u32 i = 0; i < m_ThreadCount; i++) {
						u32 TId = (u32)ThreadEntry->ClientId.UniqueThread;
						if (TId != GetCurrentThreadId()) // Ignore its own Thread
							m_ThreadList[i] = OpenThread(THREAD_SUSPEND_RESUME, false, TId);
						ThreadEntry++;
					}

					break;
				}

				if (!ProcessEntry->NextEntryOffset)
					break;
				ProcessEntry = (SYSTEM_PROCESS_INFORMATION*)((ptr)ProcessEntry->NextEntryOffset + (ptr)ProcessEntry);
			}

			VirtualFree(Memory, 0, MEM_RELEASE);
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
		handle* m_ThreadList;
	};

	class TrampolineMgr {
		struct TrampolinePage {
			void* BaseAddress;    // The BaseAddress/Location of the Page Used for the Trampolines
			qword AllocationMask; // A Mask that describes which 64b Blocks in the Page are Used
		};

	public:
		struct SyscallTrampolineX64 {
			// Thunk to Hook (Absolute Jump over RAX)
			byte ToDetour[12];
			// Instructions (up to 40 bytes) of Target followed by an absolute jump to the rest of the Target
			byte TargetThunk[40 + 12];
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
			// TODO: Finish this by properly allocating pages and managing them
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
	TrampolineMgr ThkMgr;

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
		ptr Offset = (ptr)pCode + 5;                 // Relative Offset
		*((byte*&)pCode)++ = 0xe9;                   // jmp +imm32
		*(dword*&)pCode = (dword)(Address - Offset); // Relative jump Address
	}

	status DetourFunction(                         // Detours a binary function
		_Inout_           void** ppTarget,         // Pointer to pointer containing the address of the Function to hook that will be filled with the new address redirecting to the original code
		_In_              void*  pHook,            // Pointer to the Hook Function that should be inserted
		_In_range_(5, 40) u8     InstructionLength // Count of instructionbytes to relocate into the Trampoline (must be big enough to fit a relative jump (5bytes) and small enough to fit into the trampoline (40bytes))
	) {
		if (InstructionLength < 5 || InstructionLength > 40)
			return S_CREATE(SS_WARNING, SF_ROOTKIT, SC_INVALID_PARAMETER);

		auto pTarget = *ppTarget;
		auto Trampoline = ThkMgr.AlloctateTrampolineWithinReach(pTarget);

		// Generate Bidirectional Trampoline (Thunk)
		GenerateAbsoluteJump(&Trampoline->ToDetour, (ptr)pHook);
		__movsb((byte*)&Trampoline->TargetThunk, (byte*)pTarget, InstructionLength);
		GenerateAbsoluteJump((void*)((ptr)&Trampoline->TargetThunk + InstructionLength), (ptr)pTarget + InstructionLength);
		FlushInstructionCache(GetCurrentProcess(), Trampoline, sizeof(*Trampoline));

		// Start Transaction
		ThreadUpdate tu;
		tu.SuspendThreads();

		// Detour Targetfuction to Hook
		dword Protect;
		VirtualProtect(pTarget, 8, PAGE_EXECUTE_READWRITE, &Protect);
		GenerateIntermediateRelativeJump(pTarget, (ptr)&Trampoline->ToDetour);
	#ifdef _DEBUG
		// Pad the unused bytes within the target function with breakpoints
		__stosb((byte*)((ptr)pTarget + 5), 0xcc, InstructionLength - 5);
	#endif
		VirtualProtect(pTarget, 8, Protect, &Protect);
		FlushInstructionCache(GetCurrentProcess(), pTarget, 8);

		// Set Detoured funtion to Trampoline Jumper
		*ppTarget = &Trampoline->TargetThunk;
		tu.ResumeThreads();
		return 0;
	}
}
