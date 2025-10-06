#include "types.h"

DWORD RvaToFileOffset(PE_FILE *pe, DWORD rva)
{
    // RVA == Relative File Offset, relativo a ImageBase quando o exec é loadado na memória
    // não tem mapa de memória, então é necessário converter pela section table
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
    {
        printf("CreateFileA failed (%d)\n", GetLastError());
        return FALSE;
    }

    pe->hMapping = CreateFileMappingA(pe->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!pe->hMapping)
    {
        printf("CreateFileMappingA failed (%d)\n", GetLastError());
        CloseHandle(pe->hFile);
        return FALSE;
    }

    pe->MappedView = MapViewOfFile(pe->hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pe->MappedView)
    {
        printf("MapViewOfFile failed (%d)\n", GetLastError());
        CloseHandle(pe->hMapping);
        CloseHandle(pe->hFile);
        return FALSE;
    }

    // apontando os headers DOS ** (_PE_FILE)pe->(_DOS_LAYER)Dos.Header = handle da memoria do bin (MappedView)
    pe->Dos.Header = (PIMAGE_DOS_HEADER)pe->MappedView;
    pe->Dos.OffsetToPE = pe->Dos.Header->e_lfanew;

    // cast bizarro por que a merda do windows tem 2 structs pros NtHeaders XDDD (PIMAGE_NT_HEADERS32 // PIMAGE_NT_HEADERS64)
    pe->Nt.Header = (PIMAGE_NT_HEADERS)((BYTE *)pe->MappedView + pe->Dos.OffsetToPE);
    pe->Nt.FileHeader = &pe->Nt.Header->FileHeader;
    pe->Nt.OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pe->Nt.Header->OptionalHeader;
    WORD magicNumber = pe->Nt.Header->OptionalHeader.Magic;
    if (magicNumber == 0x10B)
        pe->Type = PE32;
    else if (magicNumber == 0x20B)
        pe->Type = PE64;
    else
        pe->Type = PE_UNKNOWN;

    
    // skippando matematica de offsets pq o windows tem um macro pra isso :)
    pe->Sections.Header = IMAGE_FIRST_SECTION(pe->Nt.Header);
    pe->Sections.Count = pe->Nt.FileHeader->NumberOfSections;
    pe->Sections.OffsetToSection = (DWORD)((BYTE *)pe->Sections.Header - (BYTE *)pe->MappedView);
    
    return TRUE;
}

VOID ParseDOSLayer(PE_FILE *pe)
{
    PIMAGE_DOS_HEADER dos = pe->Dos.Header;

    printf("--------------- DOS HEADER ---------------\n");
    printf("\t0x%x\t\tMZ Signature\n", dos->e_magic);
    printf("\t0x%x\t\tBytes on last page of file\n", dos->e_cblp);
    printf("\t0x%x\t\tPages in file\n", dos->e_cp);
    printf("\t0x%x\t\tRelocations\n", dos->e_crlc);
    printf("\t0x%x\t\tSize of header in paragraphs\n", dos->e_cparhdr);
    printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dos->e_minalloc);
    printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dos->e_maxalloc);
    printf("\t0x%x\t\tInitial (relative) SS value\n", dos->e_ss);
    printf("\t0x%x\t\tInitial SP value\n", dos->e_sp);
    printf("\t0x%x\t\tChecksum\n", dos->e_csum);
    printf("\t0x%x\t\tInitial IP value\n", dos->e_ip);
    printf("\t0x%x\t\tInitial (relative) CS value\n", dos->e_cs);
    printf("\t0x%x\t\tFile address of relocation table\n", dos->e_lfarlc);
    printf("\t0x%x\t\tOverlay number\n", dos->e_ovno);
    printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dos->e_oemid);
    printf("\t0x%x\t\tOEM information; e_oemid specific\n", dos->e_oeminfo);
    printf("\t0x%x\t\tFile address of new exe header\n", dos->e_lfanew);
}

VOID ParseNTLayer(PE_FILE *pe)
{
    // Quero tirar esses 2 if-elses de 64-32 bits, mas é um saco fazer tipos genéricos, vou demorar um pouco
    // (ainda mais com o conversor junto, talvez nem compense)
    printf("\n*************** NT HEADERS ***************\n");
    WORD magic = ((PIMAGE_OPTIONAL_HEADER)pe->Nt.OptionalHeader)->Magic;
    printf("Magic: 0x%x (%s)\n", magic,
           (magic == 0x10B) ? "PE32" : (magic == 0x20B) ? "PE32+"
                                                        : "Unknown");

    if (magic == 0x20B) // PE32+
    {
        PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)pe->Nt.Header;
        PIMAGE_FILE_HEADER fh = &ntHeader64->FileHeader;
        PIMAGE_OPTIONAL_HEADER64 oh = &ntHeader64->OptionalHeader;

        // --- Signature ---
        printf("\n******* NT HEADERS *******\n");
        printf("\t0x%x\t\tSignature\n", ntHeader64->Signature);

        // --- File Header ---
        printf("\n******* FILE HEADER *******\n");
        printf("\t0x%x\t\tMachine\n", fh->Machine);
        printf("\t0x%x\t\tNumber of Sections\n", fh->NumberOfSections);
        printf("\t0x%x\t\tTime Date Stamp\n", fh->TimeDateStamp);
        printf("\t0x%x\t\tPointer to Symbol Table\n", fh->PointerToSymbolTable);
        printf("\t0x%x\t\tNumber of Symbols\n", fh->NumberOfSymbols);
        printf("\t0x%x\t\tSize of Optional Header\n", fh->SizeOfOptionalHeader);
        printf("\t0x%x\t\tCharacteristics\n", fh->Characteristics);

        // --- Optional Header ---
        printf("\n******* OPTIONAL HEADER *******\n");
        printf("\t0x%x\t\tMagic\n", oh->Magic);
        printf("\t0x%x\t\tMajor Linker Version\n", oh->MajorLinkerVersion);
        printf("\t0x%x\t\tMinor Linker Version\n", oh->MinorLinkerVersion);
        printf("\t0x%x\t\tSize Of Code\n", oh->SizeOfCode);
        printf("\t0x%x\t\tSize Of Initialized Data\n", oh->SizeOfInitializedData);
        printf("\t0x%x\t\tSize Of Uninitialized Data\n", oh->SizeOfUninitializedData);
        printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", oh->AddressOfEntryPoint);
        printf("\t0x%x\t\tBase Of Code\n", oh->BaseOfCode);
        printf("\t0x%llx\t\tImage Base\n", oh->ImageBase);
        printf("\t0x%x\t\tSection Alignment\n", oh->SectionAlignment);
        printf("\t0x%x\t\tFile Alignment\n", oh->FileAlignment);
        printf("\t0x%x\t\tMajor OS Version\n", oh->MajorOperatingSystemVersion);
        printf("\t0x%x\t\tMinor OS Version\n", oh->MinorOperatingSystemVersion);
        printf("\t0x%x\t\tMajor Image Version\n", oh->MajorImageVersion);
        printf("\t0x%x\t\tMinor Image Version\n", oh->MinorImageVersion);
        printf("\t0x%x\t\tMajor Subsystem Version\n", oh->MajorSubsystemVersion);
        printf("\t0x%x\t\tMinor Subsystem Version\n", oh->MinorSubsystemVersion);
        printf("\t0x%x\t\tWin32 Version Value\n", oh->Win32VersionValue);
        printf("\t0x%x\t\tSize Of Image\n", oh->SizeOfImage);
        printf("\t0x%x\t\tSize Of Headers\n", oh->SizeOfHeaders);
        printf("\t0x%x\t\tCheckSum\n", oh->CheckSum);
        printf("\t0x%x\t\tSubsystem\n", oh->Subsystem);
        printf("\t0x%x\t\tDllCharacteristics\n", oh->DllCharacteristics);
        printf("\t0x%llx\t\tSize Of Stack Reserve\n", oh->SizeOfStackReserve);
        printf("\t0x%llx\t\tSize Of Stack Commit\n", oh->SizeOfStackCommit);
        printf("\t0x%llx\t\tSize Of Heap Reserve\n", oh->SizeOfHeapReserve);
        printf("\t0x%llx\t\tSize Of Heap Commit\n", oh->SizeOfHeapCommit);
        printf("\t0x%x\t\tLoader Flags\n", oh->LoaderFlags);
        printf("\t0x%x\t\tNumber Of Rva And Sizes\n", oh->NumberOfRvaAndSizes);

        // --- Data Directories ---
        printf("\n******* DATA DIRECTORIES *******\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        {
            DWORD va = oh->DataDirectory[i].VirtualAddress;
            DWORD sz = oh->DataDirectory[i].Size;
            if (va || sz)
            {
                printf("[%2d] RVA: 0x%-8x  Size: 0x%-8x\n", i, va, sz);
            }
        }
    }
    else if (magic == 0x10B) // PE32
    {
        PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)pe->Nt.Header;
        PIMAGE_FILE_HEADER fh = &ntHeader32->FileHeader;
        PIMAGE_OPTIONAL_HEADER32 oh = &ntHeader32->OptionalHeader;

        // --- Signature ---
        printf("\n******* NT HEADERS *******\n");
        printf("\t0x%x\t\tSignature\n", ntHeader32->Signature);

        // --- File Header ---
        printf("\n******* FILE HEADER *******\n");
        printf("\t0x%x\t\tMachine\n", fh->Machine);
        printf("\t0x%x\t\tNumber of Sections\n", fh->NumberOfSections);
        printf("\t0x%x\t\tTime Date Stamp\n", fh->TimeDateStamp);
        printf("\t0x%x\t\tPointer to Symbol Table\n", fh->PointerToSymbolTable);
        printf("\t0x%x\t\tNumber of Symbols\n", fh->NumberOfSymbols);
        printf("\t0x%x\t\tSize of Optional Header\n", fh->SizeOfOptionalHeader);
        printf("\t0x%x\t\tCharacteristics\n", fh->Characteristics);

        // --- Optional Header ---
        printf("\n******* OPTIONAL HEADER *******\n");
        printf("\t0x%x\t\tMagic\n", oh->Magic);
        printf("\t0x%x\t\tMajor Linker Version\n", oh->MajorLinkerVersion);
        printf("\t0x%x\t\tMinor Linker Version\n", oh->MinorLinkerVersion);
        printf("\t0x%x\t\tSize Of Code\n", oh->SizeOfCode);
        printf("\t0x%x\t\tSize Of Initialized Data\n", oh->SizeOfInitializedData);
        printf("\t0x%x\t\tSize Of Uninitialized Data\n", oh->SizeOfUninitializedData);
        printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", oh->AddressOfEntryPoint);
        printf("\t0x%x\t\tBase Of Code\n", oh->BaseOfCode);
        printf("\t0x%llx\t\tImage Base\n", oh->ImageBase);
        printf("\t0x%x\t\tSection Alignment\n", oh->SectionAlignment);
        printf("\t0x%x\t\tFile Alignment\n", oh->FileAlignment);
        printf("\t0x%x\t\tMajor OS Version\n", oh->MajorOperatingSystemVersion);
        printf("\t0x%x\t\tMinor OS Version\n", oh->MinorOperatingSystemVersion);
        printf("\t0x%x\t\tMajor Image Version\n", oh->MajorImageVersion);
        printf("\t0x%x\t\tMinor Image Version\n", oh->MinorImageVersion);
        printf("\t0x%x\t\tMajor Subsystem Version\n", oh->MajorSubsystemVersion);
        printf("\t0x%x\t\tMinor Subsystem Version\n", oh->MinorSubsystemVersion);
        printf("\t0x%x\t\tWin32 Version Value\n", oh->Win32VersionValue);
        printf("\t0x%x\t\tSize Of Image\n", oh->SizeOfImage);
        printf("\t0x%x\t\tSize Of Headers\n", oh->SizeOfHeaders);
        printf("\t0x%x\t\tCheckSum\n", oh->CheckSum);
        printf("\t0x%x\t\tSubsystem\n", oh->Subsystem);
        printf("\t0x%x\t\tDllCharacteristics\n", oh->DllCharacteristics);
        printf("\t0x%llx\t\tSize Of Stack Reserve\n", oh->SizeOfStackReserve);
        printf("\t0x%llx\t\tSize Of Stack Commit\n", oh->SizeOfStackCommit);
        printf("\t0x%llx\t\tSize Of Heap Reserve\n", oh->SizeOfHeapReserve);
        printf("\t0x%llx\t\tSize Of Heap Commit\n", oh->SizeOfHeapCommit);
        printf("\t0x%x\t\tLoader Flags\n", oh->LoaderFlags);
        printf("\t0x%x\t\tNumber Of Rva And Sizes\n", oh->NumberOfRvaAndSizes);

        // --- Data Directories ---
        printf("\n******* DATA DIRECTORIES *******\n");
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
        {
            DWORD va = oh->DataDirectory[i].VirtualAddress;
            DWORD sz = oh->DataDirectory[i].Size;
            if (va || sz)
            {
                printf("[%2d] RVA: 0x%-8x  Size: 0x%-8x\n", i, va, sz);
            }
        }
    }
}

VOID ParseSections(PE_FILE *pe)
{
    printf("\n*************** SECTION HEADERS ***************\n");

    PIMAGE_SECTION_HEADER sectionHeader = pe->Sections.Header;
    WORD count = pe->Sections.Count;

    DWORD importDirectoryRVA = ((PIMAGE_OPTIONAL_HEADER)pe->Nt.OptionalHeader)
                                   ->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                   .VirtualAddress;

    PIMAGE_SECTION_HEADER importSection = NULL;

    for (int i = 0; i < count; i++, sectionHeader++)
    {
        printf("\n[%d] %s\n", i + 1, sectionHeader->Name);
        printf("\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
        printf("\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
        printf("\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
        printf("\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
        printf("\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
        printf("\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
        printf("\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
        printf("\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
        printf("\t0x%x\t\tCharacteristics\n", sectionHeader->Characteristics);

        DWORD start = sectionHeader->VirtualAddress;
        DWORD end = start + sectionHeader->Misc.VirtualSize;
        if (importDirectoryRVA >= start && importDirectoryRVA < end)
            importSection = sectionHeader;
    }

    if (importSection)
    {
        printf("\n[+] Import Directory is located in section: %s\n", importSection->Name);
    }
    else
    {
        printf("\n[!] Import Directory not found in any section!\n");
    }
}
   
