#pragma once

#ifdef TESTDLL_EXPORTS
#define TESTDLL_API __declspec(dllexport)
#else
#define TESTDLL_API __declspec(dllimport)
#endif

extern "C" TESTDLL_API int fnTestDLL(void);