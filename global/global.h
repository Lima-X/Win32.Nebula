// This File contains basic Information and data,
// that is virtually included in every File in every Project
#pragma once

#pragma region _rift standard data declarations
// CRT Specific Defines
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

// Windows (NT) Specific Defines
#define _WIN32_WINNT         0x06010000 // Windows 7 and up
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#include <windows.h>                    // Windows Header

   #define DEPRECATED      __declspec(deprecated)
// #define DEPRECATED(str) __declspec(deprecated(str))

// Standard types
typedef unsigned char      uchar;
typedef          wchar_t   wchar;
typedef unsigned short     ushort;
typedef unsigned long      ulong;
typedef unsigned long long ulonglong;

// Integer Types
typedef          char      int8;
typedef unsigned char      uint8;
typedef          short     int16;
typedef unsigned short     uint16;
typedef          int       int32;
typedef unsigned int       uint32;
typedef          long long int64;
typedef unsigned long long uint64;

// CPU Types
typedef unsigned char      byte;
typedef unsigned short     word;
typedef unsigned long      dword;
typedef unsigned long long qword;

// Special Types
typedef GUID uuid;

/* Function Status return Value:
   x=0 if Successful
   x<0 if Failure (Errorcode)
   x>0 reserved for extra Info (also Success) */
typedef signed long status;
/* equal to:
struct status {
	ulong uCode  : 31;
	ulong fError :  1;
}; */

// Raw Pointer Type
#ifdef _M_AMD64
typedef unsigned long long ptr;
#elif _M_IX86
typedef unsigned long      ptr;
#endif
#pragma endregion

// Debug
namespace dbg {
	class Benchmark {
	public:
		enum class resolution : uint32 {
			SEC = 1,
			MILLI = 1000,
			MICRO = 1000000,
			NANO = 1000000000
		};

		Benchmark(_In_ resolution res = resolution::MILLI);
		void Begin();
		uint64 End();

	private:
#ifdef _DEBUG
		static LARGE_INTEGER m_liFrequenzy;
		const  resolution    m_res;
		       LARGE_INTEGER m_liBegin;
		       LARGE_INTEGER m_liEnd;
#endif
	};

#define BreakPoint() __debugbreak()
	void TracePoint(_In_ const char* sz, _In_opt_ ...) noexcept;
	void StatusAssert(_In_ status s, _In_ const char* sz, _In_opt_ ...);

	// Temporery DllInjector, this allows for JIT debugging which manualmapping can't really do
	status InjectDllW(_In_ const wchar* szDll, _In_ dword dwPid);
}