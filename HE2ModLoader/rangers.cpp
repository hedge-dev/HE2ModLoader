#include "pch.h"
#include "cri.h"
#include "rangers.h"
#include "loader.h"
#include <string>
#include <detours.h>
#include "helpers.h"
#include "sigscanner.h"

DEFINE_SIGSCAN(FileSystemNativeLocal_OpenFileForReadingByPath, "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x81\xEC\xC0\x00\x00\x00\x48\x89\xD3\x48\x89\xCE\xE8\x00\x00\x00\x00\x48\x89\xC1\xE8\x00\x00\x00\x00\x48\x8D\x4C\x24\x38", "xxxxxxxxxxxxxxx???xxxxxxx????xxxx????xxxxx")

HOOK(void*, __fastcall, FileSystemNativeLocal_OpenFileForReadingByPath, _aFileSystemNativeLocal_OpenFileForReadingByPath, void* a1, const char* path)
{
    DWORD attributes = -1;
    for (auto& value : ReplaceDirs)
    {
        string filePath = value;
        filePath += PathSubString(path);
        attributes = GetFileAttributesA(filePath.c_str());
        if (attributes != -1)
        {
            auto newPath = filePath.c_str();
            PrintInfo("Loading File: %s", newPath);
            return originalFileSystemNativeLocal_OpenFileForReadingByPath(a1, newPath);
        }
    }

    return originalFileSystemNativeLocal_OpenFileForReadingByPath(a1, path);
}

void InitLoaderRangersMiller()
{
    // Scan save hooks
    DO_SIGSCAN(FileSystemNativeLocal_OpenFileForReadingByPath);

    // Check scans
    CHECK_SCAN(FileSystemNativeLocal_OpenFileForReadingByPath);

    INSTALL_HOOK_SIG(FileSystemNativeLocal_OpenFileForReadingByPath);
}
