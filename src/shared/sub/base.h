/* This File serves as a Base for other Headers to build on */
#pragma once

// Disable Useless/Inaccurate Warnings
#pragma warning(disable : 4100)
#pragma warning(disable : 4200)
#pragma warning(disable : 4267)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4595)
#pragma warning(disable : 4706)


// Language (C/C++) Specific
#define _CRT_SECURE_NO_WARNINGS
#define _VCRTIMP __declspec(dllimport) // Shitty hack in order to prevent the compiler from complain about
                                       // C++ overloaded inline functions being "redefined" by importing
#include <intrin.h>                    // Intrinsics (this is redundant as the windows header also includes this)

// Windows (NT) Specific
#define _WIN32_WINNT         0x06010000 // Windows 7 and up
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#include <windows.h>                    // Windows Header

// Nebula Specific
#include "sub/def.h"
#include "sub/status.h"
#include "rtl.h"
#include "..\dbg.h"

// The Macroprefix "N_" is reserved for Nebula's usage
#pragma region Loader FNV-1a Hashes
#define N_NTDLL     0xfd96b5caa3a9c6d9 // L"ntdll.dll"

#define N_NTQUERYSI 0xcac033026619e14a // "NtQuerySystemInformation"
#define N_NTQUERYDF 0x9859ea27eda9b57e // "NtQueryDirectoryFile"
#define N_RTLCOMBUF 0x2f3a7db33e2ae08b // "RtlCompressBuffer"
#define N_RTLDECBUF 0xf4e7dfe9f97daee1 // "RtlDecompressBufferEx"
#define N_RTLCOMWWS 0x2f4628d5a07bd77d // "RtlGetCompressionWorkSpaceSize"
#define N_CRTWCSCAT 0x48400801361a0cf8 // "wcscat"
#define N_CRTWCSLWR 0x830509af3f20a316 // "_wcslwr"



#define N_KRNL32DLL 0x7f1bf8b449d16c2d // L"kernel32.dll"



#define N_BCRYPTDLL 0x589716db3c6ad2b1 // L"bcrypt.dll"

#define N_BCCALGPRO 0xd05325edc3942847 // "BCryptCloseAlgorithmProvider"
#define N_BCCREHASH 0xd577120aeac34017 // "BCryptCreateHash"
#define N_BCDECRYPT 0xe813f52a0c1eb360 // "BCryptDecrypt"
#define N_BCDESHASH 0x1256b5291ddc435f // "BCryptDestroyHash"
#define N_BCDESTKEY 0x456e49222c4e5716 // "BCryptDestroyKey"
#define N_BCENCRYPT 0x7cfbe1a0e01ab5e4 // "BCryptEncrypt"
#define N_BCEXPORTK 0xd7a3e1547e22b7a4 // "BCryptExportKey"
#define N_BCFINHASH 0xbd0e01391378b228 // "BCryptFinishHash"
#define N_BCGENSYMK 0xd0258dee7a62b6ba // "BCryptGenerateSymmetricKey"
#define N_BCGENRAND 0x81b17a4c9b61eeac // "BCryptGenRandom"
#define N_BCGETPROP 0xded8482b3d5effb4 // "BCryptGetProperty"
#define N_BCHASHDAT 0x96d6540c2cfbfbf7 // "BCryptHashData"
#define N_BCIMPORTK 0x6fd72c3b719e9b35 // "BCryptImportKey"
#define N_BCOALGPRO 0x1e7273483b28159d // "BCryptOpenAlgorithmProvider"
#define N_BCSETPROP 0xaf4ca6dc1939de68 // "BCryptSetProperty"

#pragma endregion
