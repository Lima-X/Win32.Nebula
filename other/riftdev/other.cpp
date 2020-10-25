#include "global.h"

#pragma region Base Class Temporery Contstruction delegation Test
class Base {
public:
	Base(Base* pBase) {
		TracePoint("BaseClass constructed with class param\n");
	}
	Base() {
		TracePoint("BaseClass Constructed\n");
	}
	~Base() {
		TracePoint("BaseClass Deconstructor called\n");
	}
};

class Derived : private Base {
public:
	Derived()
		: Base(&Base()) {
		TracePoint("Derived Constructed\n");
	}
	~Derived() {
		TracePoint("Derived Destroyed\n");
	}

private:

};
#pragma endregion

#pragma region My Heap Singleton
class MySingleton {
public:
	static MySingleton& Instance() {
		return *Inst();
	}

private:
	MySingleton() {
		TracePoint("MySingleton Constructed");
	}
	~MySingleton() {
		TracePoint("MySingleton Destroyed");
	}

	static inline MySingleton*& Inst() {
		TracePoint("MyInstance Called");
		static Guard g;
		static MySingleton* inst;
		if (!inst)
			inst = new MySingleton;

		return inst;
	}
	class Guard {
	public:
		~Guard() {
			MySingleton*& inst = Inst();
			if (inst) {
				delete inst;
				inst = nullptr;
			}
			TracePoint("MyGuard Destroyed");
		}
	};
};
#pragma endregion

#pragma region Refrence Heap Singleton
class RefSingleton {
public:
	static RefSingleton* Instance() {
		TracePoint("RefInstance Called");
		static Guard g;
		if (!StInstance)
			StInstance = new RefSingleton();
		return StInstance;
	}

private:
	RefSingleton() {
		TracePoint("RefSingleton Constructed");
	}
	~RefSingleton() {
		TracePoint("RefSingleton Destroyed");
	}
	class Guard {
	public:
		~Guard() {
			if (RefSingleton::StInstance) {
				delete StInstance;
				StInstance = nullptr;
			}
			TracePoint("RefGuard Destroyed");
		}
	};

	static RefSingleton* StInstance;
};
RefSingleton* RefSingleton::StInstance = nullptr;
#pragma endregion

// Expects to get the address of a ntdll trampoline function
uint32 __stdcall ExtractSystemServiceNumber(uint8* caller) {
	DWORD old_protection;
	VirtualProtect(caller, 0x1000, PAGE_EXECUTE_READWRITE, &old_protection);

	uint32 e = 0, num = 0;
	while (*(caller + e) != 0xb8 && e < 12)
		e++;

	if (e >= 12) {
		VirtualProtect(caller, 0x1000, old_protection, &old_protection);
		return 0;
	}

	num = *((uint32*)(caller + e + 1));
	VirtualProtect(caller, 0x1000, old_protection, &old_protection);

	return num;
}

void other() {
	void* func = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
	uint32 servicenum = ExtractSystemServiceNumber(((uint8*)func));
}