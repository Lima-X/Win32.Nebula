@echo off

if exist _NDEBUG (
	cd Release
) else if exist _DEBUG (
	cd Debug
) else (
	goto eof
)

_riftCrypt.exe /gw "..\RIFTKEY"