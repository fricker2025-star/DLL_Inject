#include "PeParser.h"

bool ParsePEHeaders(const std::vector<BYTE>& dllData, PE_INFO& peInfo) {
    if (dllData.empty()) {
        std::cerr << "[PE Parser] Error: DLL data is empty." << std::endl;
        return false;
    }

    // Cast the beginning of the DLL data to a DOS header
    peInfo.dosHeader = (PIMAGE_DOS_HEADER)dllData.data();

    // Check for valid DOS signature
    if (peInfo.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[PE Parser] Error: Invalid DOS signature." << std::endl;
        return false;
    }

    // Get the address of the NT headers
    peInfo.ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllData.data() + peInfo.dosHeader->e_lfanew);

    // Check for valid NT signature
    if (peInfo.ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[PE Parser] Error: Invalid NT signature." << std::endl;
        return false;
    }

    // Populate file and optional headers
    peInfo.fileHeader = &peInfo.ntHeaders->FileHeader;
    peInfo.optionalHeader = &peInfo.ntHeaders->OptionalHeader;

    peInfo.ImageBase = peInfo.optionalHeader->ImageBase;
    peInfo.EntryPoint = peInfo.optionalHeader->AddressOfEntryPoint;
    peInfo.NumberOfSections = peInfo.fileHeader->NumberOfSections;
    peInfo.SizeOfImage = peInfo.optionalHeader->SizeOfImage;

    // Parse section headers
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)peInfo.ntHeaders + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < peInfo.fileHeader->NumberOfSections; ++i) {
        peInfo.sectionHeaders.push_back(*sectionHeader);
        sectionHeader++;
    }

    std::cout << "[PE Parser] Successfully parsed PE headers." << std::endl;
    return true;
}