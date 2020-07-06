// BlackBone Library
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "..\\dtBlackBone\\build\\x64\\Debug\\BlackBone.lib")
#elif _WIN32
#pragma comment(lib, "..\\dtBlackBone\\build\\Win32\\Debug\\BlackBone.lib")
#endif
#elif _NDEBUG
#ifdef _WIN64
#pragma comment(lib, "..\\dtBlackBone\\build\\x64\\Release\\BlackBone.lib")
#elif _WIN32
#pragma comment(lib, "..\\dtBlackBone\\build\\Win32\\Release\\BlackBone.lib")
#endif
#endif
#include "..\dtBlackBone\src\BlackBone\ManualMap\MMap.h"
#include"..\dtBlackBone\src\BlackBone\ManualMap\Native\NtLoader.h"

#include "_riftldr.h"
