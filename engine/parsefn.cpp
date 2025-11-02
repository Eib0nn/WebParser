#include "types.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

using json = nlohmann::json;

// helper to format any number as 0xHEX
template <typename T>
std::string to_hex(T value)
{
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << value;
    return ss.str();
}

DWORD RvaToFileOffset(PE_FILE *pe, DWORD rva)
{
    for (int i = 0; i < pe->Sections.Count; i++)
    {
        PIMAGE_SECTION_HEADER s = &pe->Sections.Header[i];
        DWORD start = s->VirtualAddress;
        DWORD end = start + s->Misc.VirtualSize;
        if (rva >= start && rva < end)
            return s->PointerToRawData + (rva - start);
    }
    return 0;
}

BOOL LoadPEFile(PE_FILE *pe, const char *filename)
{
    if (!pe || !filename)
        return FALSE;

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return FALSE;

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        close(fd);
        return FALSE;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        close(fd);
        return FALSE;
    }

    pe->fd = fd;
    pe->MappedView = map;
    pe->MappedSize = st.st_size;

    pe->Dos.Header = (PIMAGE_DOS_HEADER)pe->MappedView;
    pe->Dos.OffsetToPE = (DWORD)pe->Dos.Header->e_lfanew;

    pe->Nt.Header = (PIMAGE_NT_HEADERS32)((uint8_t *)pe->MappedView + pe->Dos.OffsetToPE);
    pe->Nt.FileHeader = &pe->Nt.Header->FileHeader;

    WORD magic = 0;
    uint8_t *optPtr = (uint8_t *)&pe->Nt.Header->OptionalHeader;
    magic = *(WORD *)optPtr;

    if (magic == 0x10B)
        pe->Type = PE32;
    else if (magic == 0x20B)
        pe->Type = PE64;
    else
        pe->Type = PE_UNKNOWN;

    uint8_t *secPtr = (uint8_t *)pe->Nt.Header + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pe->Nt.Header->FileHeader.SizeOfOptionalHeader;
    pe->Sections.Header = (PIMAGE_SECTION_HEADER)secPtr;
    pe->Sections.Count = pe->Nt.Header->FileHeader.NumberOfSections;
    pe->Sections.OffsetToSection = (DWORD)((uint8_t *)pe->Sections.Header - (uint8_t *)pe->MappedView);

    uint8_t *optBase = (uint8_t *)&pe->Nt.Header->OptionalHeader;
    // em 32x e 64x, o array DataDirectory tem size-fixado, mas na minha estrutura fica diferente,
    // ent o mais seguro é calcular o diretório de RVA import lendo em um deslocamento conhecido em relação ao OptionalHeader.
    // o deslocamento pro DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress depende do tamanho do header ent dá pra calcular com base no magic_nb.
    // tl;dr pior ideia que eu já tive na minha vida

    DWORD importRVA = 0;
    if (pe->Type == PE32)
    {
        PIMAGE_OPTIONAL_HEADER32 oh32 = (PIMAGE_OPTIONAL_HEADER32)&pe->Nt.Header->OptionalHeader;
        // DataDirectory geralmente começa dps de 96 bytes pro opt_header de 32 bits; mas não coloquei o DataDir na minha estrutura, então dá pra ler do memmap

        uint8_t *possible = (uint8_t *)oh32 + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage) + 4; 
        
        uint8_t *dataDirStart = (uint8_t *)oh32 + (offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes) + sizeof(DWORD));
        
        uint8_t *importEntry = dataDirStart + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
        importRVA = *(DWORD *)importEntry;
    }
    else if (pe->Type == PE64)
    {
        PIMAGE_OPTIONAL_HEADER64 oh64 = (PIMAGE_OPTIONAL_HEADER64)&pe->Nt.Header->OptionalHeader;
        uint8_t *dataDirStart = (uint8_t *)oh64 + (offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes) + sizeof(DWORD));
        uint8_t *importEntry = dataDirStart + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
        importRVA = *(DWORD *)importEntry;
    }

    if (importRVA == 0)
    {
        pe->Dlls.Header = NULL;
        pe->Dlls.IDTOffset = 0;
    }
    else
    {
        DWORD off = RvaToFileOffset(pe, importRVA);
        if (off == 0 || off >= pe->MappedSize)
        {
            pe->Dlls.Header = NULL;
            pe->Dlls.IDTOffset = 0;
        }
        else
        {
            pe->Dlls.Header = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t *)pe->MappedView + off);
            pe->Dlls.IDTOffset = off;
        }
    }

    return TRUE;
}

void UnloadPEFile(PE_FILE *pe)
{
    if (!pe)
        return;
    if (pe->MappedView && pe->MappedSize)
        munmap(pe->MappedView, pe->MappedSize);
    if (pe->fd >= 0)
        close(pe->fd);
}

json JsonifyDOSLayer(PE_FILE *pe)
{
    PIMAGE_DOS_HEADER dos = pe->Dos.Header;
    json j;
    j["e_magic"] = to_hex(dos->e_magic);
    j["e_cblp"] = to_hex(dos->e_cblp);
    j["e_cp"] = to_hex(dos->e_cp);
    j["e_crlc"] = to_hex(dos->e_crlc);
    j["e_cparhdr"] = to_hex(dos->e_cparhdr);
    j["e_minalloc"] = to_hex(dos->e_minalloc);
    j["e_maxalloc"] = to_hex(dos->e_maxalloc);
    j["e_ss"] = to_hex(dos->e_ss);
    j["e_sp"] = to_hex(dos->e_sp);
    j["e_csum"] = to_hex(dos->e_csum);
    j["e_ip"] = to_hex(dos->e_ip);
    j["e_cs"] = to_hex(dos->e_cs);
    j["e_lfarlc"] = to_hex(dos->e_lfarlc);
    j["e_ovno"] = to_hex(dos->e_ovno);
    j["e_oemid"] = to_hex(dos->e_oemid);
    j["e_oeminfo"] = to_hex(dos->e_oeminfo);
    j["e_lfanew"] = to_hex(dos->e_lfanew);
    return j;
}

json JsonifyNTLayer(PE_FILE *pe)
{
    json j;

    // Read magic from OptionalHeader
    uint8_t *optPtr = (uint8_t *)&pe->Nt.Header->OptionalHeader;
    WORD magic = *(WORD *)optPtr;

    j["Magic"] = to_hex(magic);
    j["Type"] = (magic == 0x10B) ? "PE32" : (magic == 0x20B) ? "PE32+"
                                                             : "Unknown";

    // Always output FileHeader regardless of magic
    PIMAGE_FILE_HEADER fh = &pe->Nt.Header->FileHeader;
    j["FileHeader"] = {
        {"Machine", to_hex(fh->Machine)},
        {"NumberOfSections", to_hex(fh->NumberOfSections)},
        {"TimeDateStamp", to_hex(fh->TimeDateStamp)},
        {"PointerToSymbolTable", to_hex(fh->PointerToSymbolTable)},
        {"NumberOfSymbols", to_hex(fh->NumberOfSymbols)},
        {"SizeOfOptionalHeader", to_hex(fh->SizeOfOptionalHeader)},
        {"Characteristics", to_hex(fh->Characteristics)}};

    // Output OptionalHeader based on detected PE type (not magic)
    if (pe->Type == PE64 || magic == 0x20B)
    {
        PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)pe->Nt.Header;
        PIMAGE_OPTIONAL_HEADER64 oh = &ntHeader->OptionalHeader;

        j["OptionalHeader"] = {
            {"Magic", to_hex(oh->Magic)},
            {"MajorLinkerVersion", to_hex(oh->MajorLinkerVersion)},
            {"MinorLinkerVersion", to_hex(oh->MinorLinkerVersion)},
            {"SizeOfCode", to_hex(oh->SizeOfCode)},
            {"SizeOfInitializedData", to_hex(oh->SizeOfInitializedData)},
            {"SizeOfUninitializedData", to_hex(oh->SizeOfUninitializedData)},
            {"AddressOfEntryPoint", to_hex(oh->AddressOfEntryPoint)},
            {"BaseOfCode", to_hex(oh->BaseOfCode)},
            {"ImageBase", to_hex(oh->ImageBase)},
            {"SectionAlignment", to_hex(oh->SectionAlignment)},
            {"FileAlignment", to_hex(oh->FileAlignment)},
            {"MajorOperatingSystemVersion", to_hex(oh->MajorOperatingSystemVersion)},
            {"MinorOperatingSystemVersion", to_hex(oh->MinorOperatingSystemVersion)},
            {"MajorImageVersion", to_hex(oh->MajorImageVersion)},
            {"MinorImageVersion", to_hex(oh->MinorImageVersion)},
            {"MajorSubsystemVersion", to_hex(oh->MajorSubsystemVersion)},
            {"MinorSubsystemVersion", to_hex(oh->MinorSubsystemVersion)},
            {"Win32VersionValue", to_hex(oh->Win32VersionValue)},
            {"SizeOfImage", to_hex(oh->SizeOfImage)},
            {"SizeOfHeaders", to_hex(oh->SizeOfHeaders)},
            {"CheckSum", to_hex(oh->CheckSum)},
            {"Subsystem", to_hex(oh->Subsystem)},
            {"DllCharacteristics", to_hex(oh->DllCharacteristics)},
            {"SizeOfStackReserve", to_hex(oh->SizeOfStackReserve)},
            {"SizeOfStackCommit", to_hex(oh->SizeOfStackCommit)},
            {"SizeOfHeapReserve", to_hex(oh->SizeOfHeapReserve)},
            {"SizeOfHeapCommit", to_hex(oh->SizeOfHeapCommit)},
            {"LoaderFlags", to_hex(oh->LoaderFlags)},
            {"NumberOfRvaAndSizes", to_hex(oh->NumberOfRvaAndSizes)}};
    }
    else if (pe->Type == PE32 || magic == 0x10B)
    {
        PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)pe->Nt.Header;
        PIMAGE_OPTIONAL_HEADER32 oh = &ntHeader->OptionalHeader;

        j["OptionalHeader"] = {
            {"Magic", to_hex(oh->Magic)},
            {"MajorLinkerVersion", to_hex(oh->MajorLinkerVersion)},
            {"MinorLinkerVersion", to_hex(oh->MinorLinkerVersion)},
            {"SizeOfCode", to_hex(oh->SizeOfCode)},
            {"SizeOfInitializedData", to_hex(oh->SizeOfInitializedData)},
            {"SizeOfUninitializedData", to_hex(oh->SizeOfUninitializedData)},
            {"AddressOfEntryPoint", to_hex(oh->AddressOfEntryPoint)},
            {"BaseOfCode", to_hex(oh->BaseOfCode)},
            {"BaseOfData", to_hex(oh->BaseOfData)},
            {"ImageBase", to_hex(oh->ImageBase)},
            {"SectionAlignment", to_hex(oh->SectionAlignment)},
            {"FileAlignment", to_hex(oh->FileAlignment)},
            {"MajorOperatingSystemVersion", to_hex(oh->MajorOperatingSystemVersion)},
            {"MinorOperatingSystemVersion", to_hex(oh->MinorOperatingSystemVersion)},
            {"MajorImageVersion", to_hex(oh->MajorImageVersion)},
            {"MinorImageVersion", to_hex(oh->MinorImageVersion)},
            {"MajorSubsystemVersion", to_hex(oh->MajorSubsystemVersion)},
            {"MinorSubsystemVersion", to_hex(oh->MinorSubsystemVersion)},
            {"Win32VersionValue", to_hex(oh->Win32VersionValue)},
            {"SizeOfImage", to_hex(oh->SizeOfImage)},
            {"SizeOfHeaders", to_hex(oh->SizeOfHeaders)},
            {"CheckSum", to_hex(oh->CheckSum)},
            {"Subsystem", to_hex(oh->Subsystem)},
            {"DllCharacteristics", to_hex(oh->DllCharacteristics)},
            {"SizeOfStackReserve", to_hex(oh->SizeOfStackReserve)},
            {"SizeOfStackCommit", to_hex(oh->SizeOfStackCommit)},
            {"SizeOfHeapReserve", to_hex(oh->SizeOfHeapReserve)},
            {"SizeOfHeapCommit", to_hex(oh->SizeOfHeapCommit)},
            {"LoaderFlags", to_hex(oh->LoaderFlags)},
            {"NumberOfRvaAndSizes", to_hex(oh->NumberOfRvaAndSizes)}};
    }

    return j;
}

json JsonifySections(PE_FILE *pe)
{
    json sections = json::array();
    PIMAGE_SECTION_HEADER sh = pe->Sections.Header;
    WORD count = pe->Sections.Count;

    for (int i = 0; i < count; i++, sh++)
    {
        json s = {
            {"Name", std::string(reinterpret_cast<char *>(sh->Name))},
            {"VirtualSize", to_hex(sh->Misc.VirtualSize)},
            {"VirtualAddress", to_hex(sh->VirtualAddress)},
            {"SizeOfRawData", to_hex(sh->SizeOfRawData)},
            {"PointerToRawData", to_hex(sh->PointerToRawData)},
            {"Characteristics", to_hex(sh->Characteristics)}};
        sections.push_back(s);
    }
    return sections;
}

json JsonifyDLLs(PE_FILE *pe)
{
    json dlls = json::array();
    if (!pe->Dlls.Header)
        return dlls;

    PIMAGE_IMPORT_DESCRIPTOR imp = pe->Dlls.Header;

    // Iterate through all import descriptors
    while (imp->Name != 0)
    {
        DWORD nameOffset = RvaToFileOffset(pe, imp->Name);
        if (nameOffset == 0 || nameOffset >= pe->MappedSize)
            break;

        char *dllName = (char *)((uint8_t *)pe->MappedView + nameOffset);

        json dll;
        dll["DLL"] = dllName;
        dll["Functions"] = json::array();

        // Use OriginalFirstThunk if available, otherwise use FirstThunk
        DWORD thunkRVA = imp->DUMMYUNIONNAME.OriginalFirstThunk ? imp->DUMMYUNIONNAME.OriginalFirstThunk : imp->FirstThunk;

        if (thunkRVA == 0)
        {
            dlls.push_back(dll);
            imp++;
            continue;
        }

        DWORD thunkOffset = RvaToFileOffset(pe, thunkRVA);
        if (thunkOffset == 0 || thunkOffset >= pe->MappedSize)
        {
            dlls.push_back(dll);
            imp++;
            continue;
        }

        // Handle both PE32 and PE64 thunk data
        if (pe->Type == PE64)
        {
            PIMAGE_THUNK_DATA64 thunk64 = (PIMAGE_THUNK_DATA64)((uint8_t *)pe->MappedView + thunkOffset);

            while (thunk64->u1.AddressOfData != 0)
            {
                // Check if imported by ordinal (high bit set)
                if (thunk64->u1.AddressOfData & 0x8000000000000000ULL)
                {
                    WORD ordinal = (WORD)(thunk64->u1.Ordinal & 0xFFFF);
                    std::stringstream ord;
                    ord << "Ordinal_" << to_hex(ordinal);
                    dll["Functions"].push_back(ord.str());
                }
                else
                {
                    // Imported by name
                    DWORD ibnOffset = RvaToFileOffset(pe, (DWORD)thunk64->u1.AddressOfData);
                    if (ibnOffset != 0 && ibnOffset < pe->MappedSize)
                    {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t *)pe->MappedView + ibnOffset);
                        dll["Functions"].push_back(std::string(ibn->Name));
                    }
                }
                thunk64++;
            }
        }
        else // PE32
        {
            PIMAGE_THUNK_DATA32 thunk32 = (PIMAGE_THUNK_DATA32)((uint8_t *)pe->MappedView + thunkOffset);

            while (thunk32->u1.AddressOfData != 0)
            {
                // Check if imported by ordinal (high bit set)
                if (thunk32->u1.AddressOfData & 0x80000000)
                {
                    WORD ordinal = (WORD)(thunk32->u1.Ordinal & 0xFFFF);
                    std::stringstream ord;
                    ord << "Ordinal_" << to_hex(ordinal);
                    dll["Functions"].push_back(ord.str());
                }
                else
                {
                    // Imported by name
                    DWORD ibnOffset = RvaToFileOffset(pe, thunk32->u1.AddressOfData);
                    if (ibnOffset != 0 && ibnOffset < pe->MappedSize)
                    {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t *)pe->MappedView + ibnOffset);
                        dll["Functions"].push_back(std::string(ibn->Name));
                    }
                }
                thunk32++;
            }
        }

        dlls.push_back(dll);
        imp++;
    }

    return dlls;
}