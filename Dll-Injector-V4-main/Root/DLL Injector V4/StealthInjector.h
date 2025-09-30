#pragma once
#include <Windows.h>
#include <string>

namespace StealthInjector
{
    void LogMessage(const std::wstring& message);
    void DisplayError(DWORD errorCode, const std::wstring& message);
    bool InjectStealthDLL(DWORD dwProcessId, const std::wstring& dllPath, bool pebUnlink);

    typedef HMODULE(WINAPI* f_LoadLibraryA)(LPCSTR lpLibFileName);
    typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
    typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

    // Structures for manual PEB parsing
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        ULONG TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID      SsSnap;
        PVOID      ProcessHeaps;
        PVOID      CriticalSectionTimeout;
        PVOID      HeapSegmentReserve;
        PVOID      HeapSegmentCommit;
        PVOID      HeapDeCommitTotalFreeThreshold;
        PVOID      HeapDeCommitFreeBlockThreshold;
        ULONG      NumberOfHeaps;
        ULONG      MaximumNumberOfHeaps;
        PVOID      ProcessHeapsList;
        PVOID      GdiSharedHandleTable;
        PVOID      ProcessStarterHelper;
        ULONG      GdiDCAttributeList;
        PVOID      LoaderLock;
        ULONG      TlsExpansionCounter;
        PVOID      TlsBitmap;
        ULONG      TlsBitmapBits[2];
        PVOID      ReadOnlySharedMemoryBase;
        PVOID      ReadOnlySharedMemoryHeap;
        PVOID      ReadOnlyStaticServerData;
        PVOID      AnsiCodePageData;
        PVOID      OemCodePageData;
        PVOID      UnicodeCaseTableData;
        ULONG      NumberOfProcessors;
        ULONG      NtGlobalFlag;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN BitField;
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PVOID ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PVOID FastPebLock;
        PVOID AtlThunkSListPtr;
        PVOID IFEOKey;
        PVOID CrossProcessFlags;
        PVOID KernelCallbackTable;
        ULONG SystemReserved;
        ULONG AtlThunkSListPtr32;
        PVOID ApiSetMap;
        ULONG TlsExpansionCounter;
        PVOID TlsBitmap;
        ULONG TlsBitmapBits[2];
        PVOID ReadOnlySharedMemoryBase;
        PVOID HotpatchInformation;
        PVOID *ReadOnlyStaticServerData;
        PVOID AnsiCodePageData;
        PVOID OemCodePageData;
        PVOID UnicodeCaseTableData;
        ULONG NumberOfProcessors;
        ULONG NtGlobalFlag;
    } PEB, *PPEB;

    void EstablishHook(DWORD dwProcessId, const std::wstring& dllPath);
    std::wstring GetDecryptedString(int stringId);
    void UnSetHook(DWORD dwProcessId, const std::wstring& dllPath);
    BOOL LoadLib(DWORD dwProcessId, const std::wstring& dllPath);
    BOOL FreeLib(DWORD dwProcessId, const std::wstring& dllPath);
    BOOL ProcessHollowingInject(DWORD dwProcessId, const std::wstring& targetProcessPath, const std::wstring& payloadPath);
    DWORD GetProcessId(LPCWSTR lpszProcessName);
    bool UnlinkModuleFromPeb(HANDLE hProcess, LPVOID moduleBase);

    // Structure to pass data to the shellcode
    typedef struct _MANUAL_MAPPING_DATA
    {
        LPVOID pDllMain;
        BYTE* pModuleBase;
        StealthInjector::f_LoadLibraryA pLoadLibraryA;
        StealthInjector::f_GetProcAddress pGetProcAddress;
        // Add other necessary fields for relocations and imports
    } MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;
}

DWORD WINAPI Shellcode(StealthInjector::PMANUAL_MAPPING_DATA pData);

