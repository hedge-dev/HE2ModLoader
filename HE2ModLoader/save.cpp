#include "pch.h"
#include "save.h"
#include <filesystem>
#include <string>
#include <detours.h>
#include "loader.h"
#include "helpers.h"
#include "sigscanner.h"

using std::wstring;

// Import
extern string* saveFilePath;
extern bool useSaveFilePath;

// TODO: Look into wrapping GetRedirectedSavePathsW
bool GetRedirectedSavePaths(const char* lpFileName, string& relativePath, string& redirectedPath)
{
    string filePath = lpFileName;

    if (filePath.find("data.sav") != std::string::npos)
    {
        size_t splitPos = filePath.substr(0, filePath.find_last_of('/') - 1).find_last_of('/');
        if (splitPos == string::npos)
        {
            PrintError("Substring failed on save file! filePath = \"%s\"", filePath.c_str());
            return false;
        }
        relativePath = filePath.substr(splitPos + 1);
        redirectedPath = *saveFilePath + "/" + relativePath;
        return true;
    }
    return false;
}
bool GetRedirectedSavePathsW(const wchar_t* lpFileName, wstring& relativePath, wstring& redirectedPath)
{
    wstring filePath = lpFileName;

    if (filePath.find(L"data.sav") != std::string::npos)
    {
        size_t splitPos = filePath.substr(0, filePath.find_last_of('/') - 1).find_last_of('/');
        if (splitPos == string::npos)
        {
            PrintError("Substring failed on save file! filePath = \"%s\"", filePath.c_str());
            return false;
        }
        relativePath = filePath.substr(splitPos + 1);
        redirectedPath = ConvertMultiByteToWideChar(*saveFilePath) + L"/" + relativePath;
        return true;
    }
    return false;
}

HOOK(HANDLE, __fastcall, KernelBaseCreateFileA, PROC_ADDRESS("Kernel32.dll", "CreateFileA"),
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile)
{
    string relativePath;
    string redirectedPath;

    if (GetRedirectedSavePaths(lpFileName, relativePath, redirectedPath))
    {
        if (dwDesiredAccess & GENERIC_WRITE)
        {
            PrintInfo("Writing save file \"%s\" to \"%s\"", relativePath.c_str(), redirectedPath.c_str());

            // Create directories
            auto dir = GetDirectoryPath(redirectedPath);
            if (!DirExists(dir))
                std::filesystem::create_directories(dir);

            // Ensure dir exists
            if (DirExists(dir))
                lpFileName = redirectedPath.c_str();
            else
                MessageBoxA(NULL, "Catastrophic Failure.\n\nFailed to create directories,\nthe game will now proceed to save normally."
                    , "Save Redirection Error!", MB_ICONERROR);
        }
        else if (dwDesiredAccess & GENERIC_READ)
        {
            if (GetFileAttributesW(ConvertMultiByteToWideChar(redirectedPath).c_str()) == -1)
            {
                PrintInfo("Loading main save for \"%s\"", relativePath.c_str());
            }
            else
            {
                PrintInfo("Loading redirected save for \"%s\" from \"%s\"", relativePath.c_str(), redirectedPath.c_str());
                lpFileName = redirectedPath.c_str();
            }
        }
    }
    return originalKernelBaseCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HOOK(HANDLE, __fastcall, KernelBaseCreateFileW, PROC_ADDRESS("Kernel32.dll", "CreateFileW"),
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile)
{
    wstring relativePath;
    wstring redirectedPath;

    if (GetRedirectedSavePathsW(lpFileName, relativePath, redirectedPath))
    {
        if (dwDesiredAccess & GENERIC_WRITE)
        {
            PrintInfo("Writing save file \"%s\" to \"%s\"", 
                std::string(relativePath.begin(), relativePath.end()).c_str(),
                std::string(redirectedPath.begin(), redirectedPath.end()).c_str());

            // Create directories
            auto dir = GetDirectoryPathW(redirectedPath);
            if (!DirExistsW(dir))
                std::filesystem::create_directories(dir);

            // Ensure dir exists
            if (DirExistsW(dir))
                lpFileName = redirectedPath.c_str();
            else
                MessageBoxA(NULL, "Catastrophic Failure.\n\nFailed to create directories,\nthe game will now proceed to save normally."
                    , "Save Redirection Error!", MB_ICONERROR);
        }
        else if (dwDesiredAccess & GENERIC_READ)
        {
            if (GetFileAttributesW(redirectedPath.c_str()) == -1)
            {
                PrintInfo("Loading main save for \"%s\"", std::string(relativePath.begin(), relativePath.end()).c_str());
            }
            else
            {
                PrintInfo("Loading redirected save for \"%s\" from \"%s\"",
                    std::string(relativePath.begin(), relativePath.end()).c_str(),
                    std::string(redirectedPath.begin(), redirectedPath.end()).c_str());
                lpFileName = redirectedPath.c_str();
            }
        }
    }
    return originalKernelBaseCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HOOK(DWORD, __fastcall, Kernel32GetFileAttributesA, PROC_ADDRESS("Kernel32.dll", "GetFileAttributesA"), LPCSTR lpFileName)
{
    string relativePath;
    string redirectedPath;

    if (GetRedirectedSavePaths(lpFileName, relativePath, redirectedPath))
    {
        if (originalKernel32GetFileAttributesA(redirectedPath.c_str()) != -1)
        {
            lpFileName = redirectedPath.c_str();
        }
    }
    return originalKernel32GetFileAttributesA(lpFileName);
}

HOOK(HANDLE, __fastcall, Kernel32CreateFileTransactedW, PROC_ADDRESS("Kernel32.dll", "CreateFileTransactedW"),
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile,
    HANDLE                hTransaction,
    PUSHORT               pusMiniVersion,
    PVOID                 lpExtendedParameter)
{
    wstring relativePath;
    wstring redirectedPath;

    if (GetRedirectedSavePathsW(lpFileName, relativePath, redirectedPath))
    {
        if (dwDesiredAccess & GENERIC_WRITE)
        {
            PrintInfo("Writing save file \"%s\" to \"%s\"", 
                std::string(relativePath.begin(), relativePath.end()).c_str(),
                std::string(redirectedPath.begin(), redirectedPath.end()).c_str());

            // Create directories
            auto dir = GetDirectoryPathW(redirectedPath);
            if (!DirExistsW(dir))
                std::filesystem::create_directories(dir);

            // Ensure dir exists
            if (DirExistsW(dir))
                lpFileName = redirectedPath.c_str();
            else
                MessageBoxA(NULL, "Catastrophic Failure.\n\nFailed to create directories,\nthe game will now proceed to save normally."
                    , "Save Redirection Error!", MB_ICONERROR);
        }
        else if (dwDesiredAccess & GENERIC_READ)
        {
            if (GetFileAttributesW(redirectedPath.c_str()) == -1)
            {
                PrintInfo("Loading main save for \"%s\"", std::string(relativePath.begin(), relativePath.end()).c_str());
            }
            else
            {
                PrintInfo("Loading redirected save for \"%s\" from \"%s\"",
                    std::string(relativePath.begin(), relativePath.end()).c_str(),
                    std::string(redirectedPath.begin(), redirectedPath.end()).c_str());
                lpFileName = redirectedPath.c_str();
            }
        }
    }
    return originalKernel32CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, lpExtendedParameter);
}

HOOK(DWORD, __fastcall, Kernel32GetFileAttributesTransactedW, PROC_ADDRESS("Kernel32.dll", "GetFileAttributesTransactedW"),
    LPCWSTR                lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation,
    HANDLE                 hTransaction)
{
    wstring relativePath;
    wstring redirectedPath;

    if (GetRedirectedSavePathsW(lpFileName, relativePath, redirectedPath))
    {
        if (originalKernel32GetFileAttributesTransactedW(redirectedPath.c_str(), fInfoLevelId, lpFileInformation, hTransaction) != -1)
        {
            lpFileName = redirectedPath.c_str();
        }
    }
    return originalKernel32GetFileAttributesTransactedW(lpFileName, fInfoLevelId, lpFileInformation, hTransaction);
}


void InitSaveRedirection()
{
    if (useSaveFilePath)
    {
        // So apparently rangers uses A for reading and W for writing on 1.01
        INSTALL_HOOK(KernelBaseCreateFileA);
        INSTALL_HOOK(Kernel32GetFileAttributesA);
        INSTALL_HOOK(KernelBaseCreateFileW);

        // miller uses the transacted functions
        INSTALL_HOOK(Kernel32CreateFileTransactedW);
        INSTALL_HOOK(Kernel32GetFileAttributesTransactedW);
    }

}