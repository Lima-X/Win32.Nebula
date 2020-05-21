#pragma once
#include "..\_rift\_rift_shared.h"

// Why did i even bother making this macro for this
// if this file doesn't get used outside the dll anyways -.-
#ifdef _WINDLL
#define DLLAPI __declspec(dllexport)
#else
#define DLLAPI __declspec(dllimport)
#endif // _WINDLL

DLLAPI BOOL fnDllInit(int a);