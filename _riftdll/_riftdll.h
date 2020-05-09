#ifndef _riftdll_HIG
#define _riftdll_HIG

#ifdef _WINDLL
#include "..\_rift\_rift_shared.h"
#define DLLEXPORT __declspec(dllexport)
#endif // _WINDLL

DLLEXPORT BOOL fnDllInit(pEpTDll pData);

#endif // !_riftdll_HIG