#include "types.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

extern BOOL LoadPEFile(PE_FILE *pe, const char *filename);
extern json JsonifyDOSLayer(PE_FILE *pe);
extern json JsonifyNTLayer(PE_FILE *pe);
extern json JsonifySections(PE_FILE *pe);
extern json JsonifyDLLs(PE_FILE *pe);

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "{\"error\": \"No file path provided\"}" << std::endl;
        return 1;
    }

    const char *filename = argv[1];
    PE_FILE pe;

    if (!LoadPEFile(&pe, filename))
    {
        std::cerr << "{\"error\": \"Failed to load file\"}" << std::endl;
        return 1;
    }

    json output;
    output["File"] = filename;
    output["Type"] = (pe.Type == PE32) ? "PE32" : (pe.Type == PE64) ? "PE64"
                                                                    : "Unknown";
    output["DOSHeader"] = JsonifyDOSLayer(&pe);
    output["NTHeaders"] = JsonifyNTLayer(&pe);
    output["Sections"] = JsonifySections(&pe);
    output["Imports"] = JsonifyDLLs(&pe);

    std::cout << output.dump(4) << std::endl;
    return 0;
    /*
    PE_FILE pe;
    const char* filename = "helloworld.exe";
    _LOAD_PE_FILE* loadFile = &LoadPEFile;
    _PARSE_DOS_LAYER *ParseDos = &ParseDOSLayer;
    _PARSE_NT_LAYER *ParseNT = &ParseNTLayer;
    _PARSE_SECTIONS* ParseSec = &ParseSections;
    _PARSE_DLL_IMPORTS* ParseDll = &ParseDLL;
    BOOL hPE = loadFile(&pe, filename);
    ParseDos(&pe);
    ParseNT(&pe);
    ParseSec(&pe);
    ParseDll(&pe);
    UnmapViewOfFile(mappedView);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    */
}
