#include "framework.h"
#include "StealthInjector.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <fstream>  // For file operations
#include <vector>   // For storing file data
#include "PeParser.h"  // Include the PE Parser header

// Function to get process ID by name
DWORD GetProcessIdByName(const wchar_t* processName)
{
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Error: CreateToolhelp32Snapshot failed. GetLastError: " << GetLastError() << std::endl;
        return 0;
    }

    if (Process32First(snapshot, &processEntry))
    {
        do
        {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0)
            {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

int main()
{
    std::wcout << L"Injector started." << std::endl;
    fflush(stdout);

    std::wstring dllPath = L"C:\\Users\\frecc\\Desktop\\Dll-Injector-V4-main\\Root\\TestDLL\\TestDLL.dll";  // Path to TestDLL.dll
    std::wstring processName = L"RobloxPlayerBeta.exe";  // Target RobloxPlayerBeta.exe

    // Read DLL file into a buffer
    std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
    if (!dllFile.is_open())
    {
        std::wcerr << L"Error: Could not open DLL file: " << dllPath << std::endl;
        fflush(stderr);
        return 1;
    }

    std::streampos fileSize = dllFile.tellg();
    std::vector<char> dllData(fileSize);
    dllFile.seekg(0);
    dllFile.read(dllData.data(), fileSize);
    dllFile.close();

    std::vector<BYTE> dllDataByte(dllData.begin(), dllData.end());
    PE_INFO peInfo;
    if (!ParsePEHeaders(dllDataByte, peInfo))
    {
        std::wcerr << L"Error: Failed to parse PE headers of " << dllPath << std::endl;
        fflush(stderr);
        return 1;
    }

    std::wcout << L"PE Header Information for " << dllPath << std::endl;
    std::wcout << L"  Image Base: 0x" << std::hex << peInfo.ImageBase << std::endl;
    std::wcout << L"  Entry Point: 0x" << std::hex << peInfo.EntryPoint << std::endl;
    std::wcout << L"  Number of Sections: " << std::dec << peInfo.NumberOfSections << std::endl;
    std::wcout << L"  Size of Image: " << std::dec << peInfo.SizeOfImage << std::endl;
    fflush(stdout);

    std::wcout << L"Attempting to find process: " << processName << std::endl;
    fflush(stdout);
    // Get process ID by name
    DWORD processId = GetProcessIdByName(processName.c_str());
    if (processId == 0)
    {
        std::wcerr << L"Error: Process '" << processName << L"' not found." << std::endl;
        fflush(stderr);
        return 1;
    }
    std::wcout << L"Process found with ID: " << processId << std::endl;
    fflush(stdout);

    std::wcout << L"Attempting to open process." << std::endl;
    fflush(stdout);
    // Open process with necessary permissions
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        std::wcerr << L"Error: Could not open process. GetLastError: " << GetLastError() << std::endl;
        fflush(stderr);
        return 1;
    }
    std::wcout << L"Process opened successfully." << std::endl;
    fflush(stdout);

    // Stealthy DLL injection logic
    if (!StealthInjector::InjectStealthDLL(processId, dllPath, false))
    {
        std::wcerr << L"Error: Stealth DLL injection failed. GetLastError: " << GetLastError() << std::endl;
        fflush(stderr);
        CloseHandle(hProcess);
        return 1;
    }
    std::wcout << L"DLL injected successfully!" << std::endl;
    fflush(stdout);

    // Clean up
    CloseHandle(hProcess);
    std::wcout << L"Cleanup complete." << std::endl;
    fflush(stdout);

    std::wcin.get();  // Pause the console
    return 0;
}
