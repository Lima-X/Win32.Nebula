#pragma once

#pragma region _rift standard Data declarations
// Declaration-Specifications
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
   x>0 reserved for extra Info (also Success)

   Highest bit enabled (Bit31) indicates error */
typedef _Success_(return >= 0) signed long status;



// Raw Pointer Type
#ifdef _M_AMD64
typedef unsigned long long ptr;
#elif _M_IX86
typedef unsigned long      ptr;
#endif
#pragma endregion
