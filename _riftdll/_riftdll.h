#ifndef _riftdll_HIG
#define _riftdll_HIG

#include "..\_rift\_rift_shared.h"

#ifdef _WINDLL
#define DLL __declspec(dllexport)
#else
#define DLL __declspec(dllimport)
#endif // _WINDLL

#endif // !_riftdll_HIG