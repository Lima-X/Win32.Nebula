@echo off

if exist _NDEBUG (
	cd Release
) else if exist _DEBUG (
	cd Debug
) else (
	goto eof
)

_riftCrypt.exe /de "..\RIFTDLL" "_riftdll.dll"
_riftCrypt.exe /de "..\RIFTINJECT32" "_riftInject32.exe"
_riftCrypt.exe /de "..\RIFTINJECT64" "_riftInject64.exe"
_riftCrypt.exe /de "..\RIFTROOT32" "_riftRoot32.dll"
_riftCrypt.exe /de "..\RIFTROOT64" "_riftRoot64.dll"

pause