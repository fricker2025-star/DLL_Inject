@echo off

REM Build the solution
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" "C:\Users\frecc\Desktop\Dll-Injector-V4-main\Root\DLL Injector V4.sln" /p:Configuration=Release /p:Platform=x64

if %ERRORLEVEL% neq 0 (
    echo Build failed.
    pause
    exit /b 1
)

echo Build completed successfully.
pause