// This File contains basic Information and data,
// that is virtually included in every File in every Project
#pragma once

// CRT Specific
#define _CRT_SECURE_NO_WARNINGS
#ifdef  __cplusplus
#include <memory>
#else
#include <memory.h>
#endif

// Windows (NT) Specific
#define _WIN32_WINNT         0x06010000 // Windows 7 and up
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#include <windows.h>                    // Windows Header


// _rift Specific
#include "def.h"
#include "debug.h"

#ifdef __cplusplus
#pragma region Utility
constexpr uint32 RoundUpToMulOfPow2(uint32 num, uint32 mul) {
	return (num + (mul - 1)) & (0 - mul);
}
constexpr uint32 RoundUpToNearestMul(uint32 num, uint32 mul) {
	return ((num + (mul - 1)) / mul) * mul;
}
constexpr uint32 Max(uint32 num1, uint32 num2) {
	return num1 > num2 ? num1 : num2;
}
#pragma endregion
#endif