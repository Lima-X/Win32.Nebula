@echo off

if exist _NDEBUG (
	cd Release
) else if exist _DEBUG (
	cd Debug
) else (
	goto eof
)

_riftTool.exe /gk "..\RIFTWKEY"
_riftTool.exe /gt "..\RIFTWKEY" "..\RIFTTEST"
pause