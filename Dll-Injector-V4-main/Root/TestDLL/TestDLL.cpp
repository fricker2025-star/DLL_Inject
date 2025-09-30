// TestDLL.cpp : Defines the exported functions for the DLL.
#include "pch.h"
#include "framework.h"
#include "TestDLL.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("TestDLL Injected!\n");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugStringA("TestDLL Detached!\n");
        break;
    }
    return TRUE;
}

// This is an example of an exported function.
extern "C" TESTDLL_API int fnTestDLL(void)
{
    return 0;
}