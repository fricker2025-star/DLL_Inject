@echo off
CALL "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
msbuild "Root\DLL Injector V4.sln" /p:Configuration=Release /p:Platform=x64