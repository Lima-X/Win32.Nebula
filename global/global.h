// This File contains basic Information and data,
// that is virtually included in every File in every Project
#pragma once

#include <windows.h>

/* Windows Naming Convention */
#define DEPRECATED __declspec(deprecated)
typedef GUID         uuid;

// Standard types
typedef unsigned char  uchar;
typedef unsigned short wchar;
typedef unsigned long  ushort;
typedef unsigned long  ulong;
typedef unsigned int   uint;
typedef unsigned char  byte;
typedef unsigned short word;
typedef unsigned long  dword;

/* Function Status return Value:
   x=0 if Successful
   x<0 if Failure (Errorcode)
   x>0 reserved for extra Info (also Success) */
typedef signed long status;

// Raw Pointer Type
#ifdef _WIN64
typedef unsigned long long ptr;
#elif _WIN32
typedef unsigned long      ptr;
#endif
