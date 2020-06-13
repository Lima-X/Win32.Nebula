#pragma once
#include "..\_rift\_rift_shared.h"

// Why did i even bother making this macro for this
// if this file doesn't get used outside the dll anyways -.-
#ifdef _WINDLL
#define DLLEX __declspec(dllexport)
#else
#define DLLEX __declspec(dllimport)
#endif // _WINDLL

DLLEX BOOL EDllInit(_In_ PPIB pib);