#pragma once

#include "..\core\shared\shared.h"

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

/* RPC DebugObject UAC Bypass/Exploit */
#ifdef __cplusplus

// BlackBone Library
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "..\\..\\other\\dtBlackBone\\build\\x64\\Debug\\BlackBone.lib")
#elif _WIN32
#pragma comment(lib, "..\\..\\other\\dtBlackBone\\build\\Win32\\Debug\\BlackBone.lib")
#endif
#elif _NDEBUG
#ifdef _WIN64
#pragma comment(lib, "..\\..\\other\\dtBlackBone\\build\\x64\\Release\\BlackBone.lib")
#elif _WIN32
#pragma comment(lib, "..\\..\\other\\dtBlackBone\\build\\Win32\\Release\\BlackBone.lib")
#endif
#endif
#include "..\..\other\dtBlackBone\src\BlackBone\ManualMap\MMap.h"

#else
#pragma comment(lib, "rpcrt4.lib")
#include <rpcndr.h>
#include <rpc.h>
#include <oaidl.h>
#include <ocidl.h>
#include "appinfo32.h"
#endif



// Why did i even bother making this macro for this
// if this file doesn't get used outside the dll anyways -.-
#ifdef _WINDLL
#define DLLEX __declspec(dllexport)
#else
#define DLLEX __declspec(dllimport)
#endif // _WINDLL

#ifdef __cplusplus
DLLEX BOOL EDllInit(_In_ PIB* pib);
#endif