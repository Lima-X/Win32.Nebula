// This File contains basic Information and data,
// that is virtually included in every File in every Project
#pragma once

// CRT Specific Defines
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

// Windows (NT) Specific Defines
#define _WIN32_WINNT 0x06010000 // Windows 7
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

   #define DEPRECATED      __declspec(deprecated)
// #define DEPRECATED(str) __declspec(deprecated(str))

// Standard types
   typedef unsigned char    uchar;
   typedef          wchar_t wchar;
// typedef unsigned short   ushort;
   typedef unsigned long    ulong;

// Integer Types
   typedef          char      int8;
   typedef unsigned char      uint8;
   typedef          short     int16;
   typedef unsigned short     uint16;
   typedef          int       int32;
   typedef unsigned int       uint32;
// typedef          long long int64;
// typedef unsigned long long uint64;

// CPU Types
   typedef unsigned char      byte;
   typedef unsigned short     word;
   typedef unsigned long      dword;
// typedef unsigned long long qword

// Special Types
typedef GUID uuid;

/* Function Status return Value:
   x=0 if Successful
   x<0 if Failure (Errorcode)
   x>0 reserved for extra Info (also Success) */
typedef signed long status;
/*
struct status {
	ulong uCode  : 31;
	ulong fError :  1;
};
*/

// Raw Pointer Type
#ifdef _WIN64
typedef unsigned long long ptr;
#elif _WIN32
typedef unsigned long      ptr;
#endif
