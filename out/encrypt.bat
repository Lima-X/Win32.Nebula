@echo off
cd bin

_riftTool.exe /ec "_riftdll.dll" "..\RIFTWKEY" "..\RIFTDLL"
_riftTool.exe /ec "_riftInject32.exe" "..\RIFTWKEY" "..\RIFTINJECT32"
_riftTool.exe /ec "_riftInject64.exe" "..\RIFTWKEY" "..\RIFTINJECT64"
_riftTool.exe /ec "_riftRoot32.dll" "..\RIFTWKEY" "..\RIFTROOT32"
_riftTool.exe /ec "_riftRoot64.dll" "..\RIFTWKEY" "..\RIFTROOT64"

pause