// Defines Common/Standard Datatypes used by Nebula
#pragma once

#pragma region Datatype Declarations
// Standard Types for Strings
typedef          wchar_t   wchar;

// Integer Types
typedef          char      i8;
typedef          short     i16;
typedef          int       i32;
typedef          long long i64;
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

// CPU Types
typedef unsigned char      byte;
typedef unsigned short     word;
typedef unsigned long      dword;
typedef unsigned long long qword;

// Pointer Types
#ifdef _M_X64
typedef unsigned long long ptr;    // A pointer as a raw value used for pointer arithmetic (prefered over "void*")
typedef unsigned long long poly;   // A polymorthic scalar type that can be used to store anything fitting
typedef          void*     handle; // A handle is a polymorthic type that stores a reference or value associated to an object
                                   // this value has to be translated and processed by the corresponding api (similar to WinAPI's)
#elif _M_IX86
typedef unsigned long  ptr;
typedef unsigned long  poly;
typedef          void* handle;
#endif
#pragma endregion

#pragma region Standard Macros
#ifdef _M_X64
#define __x64call
#else
#define __x64call INVALID_CALLING_CONVENTION // This cause a compiler error
#endif

#define GENERIC_READWRITE   0xc0000000 // (GENERIC_READ | GENERIC_WRITE)

#define DEPRECATED             __declspec(deprecated)
#define DEPRECATED_STR(String) __declspec(deprecated(String))

#define IMPORT                 __declspec(dllimport)
#define EXPORT                 __declspec(dllexport)
#define NOINLINE               __declspec(noinline)

#define ALLOC_CODE(Section)    __declspec(code_seg(Section))
#define ALLOC_DATA(Section)    __declspec(allocate(Section))
#pragma endregion
