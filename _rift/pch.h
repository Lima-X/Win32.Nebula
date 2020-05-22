#pragma once
#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <psapi.h>
#include <strsafe.h>

#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>

#include "..\Detours-4.0.1\include\detours.h"