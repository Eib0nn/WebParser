#include "types.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <string>

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
    pe->hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pe->hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    pe->hMapping = CreateFileMappingA(pe->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!pe->hMapping)
    {
        CloseHandle(pe->hFile);
        return FALSE;
    }

    pe->MappedView = MapViewOfFile(pe->hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pe->MappedView)
    {
        CloseHandle(pe->hMapping);
        CloseHandle(pe->hFile);
        return FALSE;
    }

    pe->Dos.Header = (PIMAGE_DOS_HEADER)pe->MappedView;
    pe->Dos.OffsetToPE = pe->Dos.Header->e_lfanew;

    pe->Nt.Header = (PIMAGE_NT_HEADERS)((BYTE *)pe->MappedView + pe->Dos.OffsetToPE);
    pe->Nt.FileHeader = &pe->Nt.Header->FileHeader;
    pe->Nt.OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pe->Nt.Header->OptionalHeader;

    WORD magic = pe->Nt.Header->OptionalHeader.Magic;
    if (magic == 0x10B)
        pe->Type = PE32;
    else if (magic == 0x20B)
        pe->Type = PE64;
    else
        pe->Type = PE_UNKNOWN;

    pe->Sections.Header = IMAGE_FIRST_SECTION(pe->Nt.Header);
    pe->Sections.Count = pe->Nt.FileHeader->NumberOfSections;
    pe->Sections.OffsetToSection = (DWORD)((BYTE *)pe->Sections.Header - (BYTE *)pe->MappedView);

    DWORD rva = pe->Nt.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD off = RvaToFileOffset(pe, rva);
    pe->Dlls.Header = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pe->MappedView + off);
    pe->Dlls.IDTOffset = off;
    return TRUE;
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
    WORD magic = ((PIMAGE_OPTIONAL_HEADER)pe->Nt.OptionalHeader)->Magic;

    j["Magic"] = to_hex(magic);
    j["Type"] = (magic == 0x10B) ? "PE32" : (magic == 0x20B) ? "PE32+"
                                                             : "Unknown";

    if (magic == 0x20B)
    {
        PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)pe->Nt.Header;
        PIMAGE_FILE_HEADER fh = &ntHeader->FileHeader;
        PIMAGE_OPTIONAL_HEADER64 oh = &ntHeader->OptionalHeader;

        j["FileHeader"] = {
            {"Machine", to_hex(fh->Machine)},
            {"NumberOfSections", to_hex(fh->NumberOfSections)},
            {"TimeDateStamp", to_hex(fh->TimeDateStamp)},
            {"Characteristics", to_hex(fh->Characteristics)}};

        j["OptionalHeader"] = {
            {"ImageBase", to_hex(oh->ImageBase)},
            {"AddressOfEntryPoint", to_hex(oh->AddressOfEntryPoint)},
            {"SizeOfImage", to_hex(oh->SizeOfImage)},
            {"Subsystem", to_hex(oh->Subsystem)},
            {"DllCharacteristics", to_hex(oh->DllCharacteristics)}};
    }
    else if (magic == 0x10B)
    {
        PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)pe->Nt.Header;
        PIMAGE_FILE_HEADER fh = &ntHeader->FileHeader;
        PIMAGE_OPTIONAL_HEADER32 oh = &ntHeader->OptionalHeader;

        j["FileHeader"] = {
            {"Machine", to_hex(fh->Machine)},
            {"NumberOfSections", to_hex(fh->NumberOfSections)},
            {"TimeDateStamp", to_hex(fh->TimeDateStamp)},
            {"Characteristics", to_hex(fh->Characteristics)}};

        j["OptionalHeader"] = {
            {"ImageBase", to_hex(oh->ImageBase)},
            {"AddressOfEntryPoint", to_hex(oh->AddressOfEntryPoint)},
            {"SizeOfImage", to_hex(oh->SizeOfImage)},
            {"Subsystem", to_hex(oh->Subsystem)},
            {"DllCharacteristics", to_hex(oh->DllCharacteristics)}};
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

    while (imp->Name)
    {
        DWORD nameOffset = RvaToFileOffset(pe, imp->Name);
        char *dllName = (char *)((BYTE *)pe->MappedView + nameOffset);

        json dll;
        dll["DLL"] = dllName;
        dll["Functions"] = json::array();

        DWORD thunkRVA = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        DWORD thunkOffset = RvaToFileOffset(pe, thunkRVA);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE *)pe->MappedView + thunkOffset);

        while (thunk->u1.AddressOfData)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                std::stringstream ord;
                ord << "Ordinal_" << to_hex(IMAGE_ORDINAL(thunk->u1.Ordinal));
                dll["Functions"].push_back(ord.str());
            }
            else
            {
                DWORD ibnOffset = RvaToFileOffset(pe, thunk->u1.AddressOfData);
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pe->MappedView + ibnOffset);
                dll["Functions"].push_back(ibn->Name);
            }
            thunk++;
        }

        dlls.push_back(dll);
        imp++;
    }

    return dlls;
}
