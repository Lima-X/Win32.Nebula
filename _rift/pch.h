#pragma once
#ifndef _PCH_HIG
#define _PCH_HIG

#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <strsafe.h>

#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>

#endif // !_PCH_HIG