#pragma once

#include <Windows.h>
#include <ntstatus.h>
#include <Shlobj.h>
#include <KnownFolders.h>
#include <strsafe.h>
#include <PathCch.h>

/* RPC DebugObject UAC Bypass/Exploit */
#pragma comment(lib, "rpcrt4.lib")
#include <rpcndr.h>
#include <rpc.h>
#include <oaidl.h>
#include <ocidl.h>
#include "appinfo32.h"