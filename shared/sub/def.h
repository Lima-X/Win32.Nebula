// Defines Common/Standard Datatypes used by Win32.riftV2
#pragma once

#pragma region Datatype Declarations
// Declaration-Specifications
#define DEPRECATED      __declspec(deprecated)
// #define DEPRECATED(str) __declspec(deprecated(str))

// Standard Types for Strings
typedef          wchar_t   wchar;

// Integer Types
typedef          char      i8;
typedef unsigned char      u8;
typedef          short     i16;
typedef unsigned short     u16;
typedef          int       i32;
typedef unsigned int       u32;
typedef          long long i64;
typedef unsigned long long u64;

// CPU Types
typedef unsigned char      byte;
typedef unsigned short     word;
typedef unsigned long      dword;
typedef unsigned long long qword;

// Pointer Types
#ifdef _M_AMD64
typedef unsigned long long ptr;
typedef unsigned long long poly;
#elif _M_IX86
typedef unsigned long      ptr;
typedef unsigned long      poly;
#endif
#pragma endregion
