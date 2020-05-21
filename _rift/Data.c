#include "pch.h"
#include "_rift.h"

const WCHAR szConsoleTitle[] = L"[_rift-Loader] by Lima X [L4X] (dev-build)";
const UINT8 nConsoleTitleLen = sizeof(szConsoleTitle) / sizeof(WCHAR);

const WCHAR szSelfDelBat[] = {
	L"@echo off\n"
	L"IfEx:\n"
	L"del \"%s\" / f\n"
	L"\tif exist \"%s\" (\n"
	L"\t\tgoto IfEx\n"
	L"\t)\n"
	L"del \"%s\" / f"
};

const WCHAR szCharSetBASE82[] = {
	L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	L"abcdefghijklmnopqrstuvwxyz"
	L"^1234567890´°!§$&()=`{[]},"
	L".-;_"
};