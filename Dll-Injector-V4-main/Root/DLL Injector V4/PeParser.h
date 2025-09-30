#pragma once

#include <windows.h>
#include <winnt.h> // For IMAGE_NT_HEADERS, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER, etc.
#include <iostream>
#include <vector>

// Structure to hold parsed PE information
typedef struct _PE_INFO {
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_FILE_HEADER fileHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sectionHeaders;
    ULONGLONG ImageBase;
    DWORD EntryPoint;
    DWORD NumberOfSections;
    DWORD SizeOfImage;
} PE_INFO, *PPE_INFO;

// Function to parse PE headers
bool ParsePEHeaders(const std::vector<BYTE>& dllData, PE_INFO& peInfo);