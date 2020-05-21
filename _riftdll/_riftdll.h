#pragma once

#ifdef _WINDLL
#include "..\_rift\_rift_shared.h"
#define DLLAPI __declspec(dllexport)
#else
#define DLLAPI __declspec(dllimport)
#endif // _WINDLL

BOOL DLLAPI fnDllInit();