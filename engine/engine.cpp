#include "types.h"
#include <nlohmann/json.hpp>
#include <string>
#include <iostream>
#include <cstdlib>
#include <cstring>

using json = nlohmann::json;

extern BOOL LoadPEFile(PE_FILE *pe, const char *filename);
extern void UnloadPEFile(PE_FILE *pe);
extern json JsonifyDOSLayer(PE_FILE *pe);
extern json JsonifyNTLayer(PE_FILE *pe);
extern json JsonifySections(PE_FILE *pe);
extern json JsonifyDLLs(PE_FILE *pe);

extern "C"
{
    char *parse_file(const char *filename)
    {
        if (!filename)
            return nullptr;

        PE_FILE pe = {};
        if (!LoadPEFile(&pe, filename))
        {
            const char *err = "{\"error\": \"Failed to load file\"}";
            char *out = (char *)malloc(strlen(err) + 1);
            strcpy(out, err);
            return out;
        }

        json output;
        output["File"] = filename;
        output["Type"] = (pe.Type == PE32) ? "PE32" : (pe.Type == PE64) ? "PE64"
                                                                        : "Unknown";
        output["DOSHeader"] = JsonifyDOSLayer(&pe);
        output["NTHeaders"] = JsonifyNTLayer(&pe);
        output["Sections"] = JsonifySections(&pe);
        output["Imports"] = JsonifyDLLs(&pe);

        std::string s = output.dump(4);
        char *res = (char *)malloc(s.size() + 1);
        memcpy(res, s.c_str(), s.size() + 1);

        UnloadPEFile(&pe);
        return res;
    }

    void free_parser_output(char *p)
    {
        if (p)
            free(p);
    }
}