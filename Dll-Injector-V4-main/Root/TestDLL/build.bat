@echo off

REM Set the path to Visual Studio's VC environment variables script
REM Adjust this path based on your Visual Studio installation
set "VS_VCVARS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VS_VCVARS_PATH%" (
    echo Error: Visual Studio vcvars64.bat not found at "%VS_VCVARS_PATH%"
    echo Please update the path in build.bat to your Visual Studio installation.
    goto :eof
)

call "%VS_VCVARS_PATH%" && (
    REM Compile the DLL
    cl /LD /EHsc TestDLL.cpp /DTESTDLL_EXPORTS /link user32.lib /OUT:TestDLL.dll
)

@echo on
pause