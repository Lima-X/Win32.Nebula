#ifndef _riftdll_HIG
#define _riftdll_HIG

#ifdef _WINDLL
#include "..\_rift\_rift_shared.h"
#define DLLAPI __declspec(dllexport)
#else
#define DLLAPI __declspec(dllimport)
#endif // _WINDLL

BOOL DLLAPI fnDllInit(pEpTDll pData);

#endif // !_riftdll_HIG