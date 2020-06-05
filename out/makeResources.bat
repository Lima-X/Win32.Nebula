@echo off

if exist _NDEBUG (
	cd Release
) else if exist _DEBUG (
	cd Debug
) else (
	goto eof
)

_riftCrypt.exe /gw "..\RIFTKEY"
_riftCrypt.exe /en "_riftdll.dll" "..\RIFTDLL"
_riftCrypt.exe /en "_riftInject32.exe" "..\RIFTINJECT32"
_riftCrypt.exe /en "_riftInject64.exe" "..\RIFTINJECT64"
_riftCrypt.exe /en "_riftRoot32.dll" "..\RIFTROOT32"
_riftCrypt.exe /en "_riftRoot64.dll" "..\RIFTROOT64"

pause