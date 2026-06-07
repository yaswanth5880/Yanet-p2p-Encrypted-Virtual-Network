@echo off
echo Starting YaNet Node 1 (Windows Listener) on port 9994...
cd %~dp0
.\build\Release\yanet.exe --port 9994
pause
