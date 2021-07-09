#pragma once
#include <cstdio>
#include <fstream>
#include <vector>
#include <Shlwapi.h>

#define DataPointer(type, name, address) \
	static type &name = *(type *)address

#define FastcallFunctionPointer(RETURN_TYPE, NAME, ARGS, ADDRESS) \
	static RETURN_TYPE (__fastcall * NAME)ARGS = (RETURN_TYPE (__fastcall *)ARGS)ADDRESS

#define UPDATE_FUNCTION_POINTER(NAME, ADDRESS) \
	*((void**)&NAME) = (void*)ADDRESS


static inline bool FileExists(const char* fileName)
{
    return GetFileAttributesA(fileName) != -1;
}

static inline bool dirExists(const std::string& dirName_in)
{
    DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
    if (ftyp == INVALID_FILE_ATTRIBUTES)
        return false;  //something is wrong with your path!

    if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
        return true;   // this is a directory!

    return false;    // this is not a directory!
}

static const int ModLoaderVer = 1;
static const int GameVer = 0;

enum Game
{
    Game_Unknown = 0,
    Game_Tenpex  = 1259790,
    Game_Musashi = 981890
};

struct Mod
{
    const char* Name;
    const char* Path;
};

struct ModInfo
{
    std::vector<Mod*>* ModList;
    Mod* CurrentMod;
    Game CurrentGame;
};

typedef void(__cdecl* ModInitEvent)(ModInfo* modInfo);
typedef void(__cdecl* ModCallEvent)();

// IDA Types
typedef uint64_t _QWORD;
typedef uint32_t _DWORD;
typedef uint16_t _WORD;
typedef uint8_t _BYTE;

// CPK Types
typedef char CriChar8;
typedef signed int CriSint32;
typedef unsigned int CriUint32;
typedef CriUint32 CriFsBindId;
typedef void** CriFsBinderHn;

typedef enum
{
    CRIERR_LEVEL_ERROR = 0,
    CRIERR_LEVEL_WARNING = 1,
    CRIERR_LEVEL_ENUM_BE_SINT32 = 0x7FFFFFFF
} CriErrorLevel;

typedef enum
{
    CRIFSBINDER_STATUS_NONE = 0,
    CRIFSBINDER_STATUS_ANALYZE,
    CRIFSBINDER_STATUS_COMPLETE,
    CRIFSBINDER_STATUS_UNBIND,
    CRIFSBINDER_STATUS_REMOVED,
    CRIFSBINDER_STATUS_INVALID,
    CRIFSBINDER_STATUS_ERROR,

    /* enum be 4bytes */
    CRIFSBINDER_STATUS_ENUM_BE_SINT32 = 0x7FFFFFFF
} CriFsBinderStatus;

typedef enum
{
    CRIERR_OK = 0,
    CRIERR_NG = -1,
    CRIERR_INVALID_PARAMETER = -2,
    CRIERR_FAILED_TO_ALLOCATE_MEMORY = -3,
    CRIERR_UNSAFE_FUNCTION_CALL = -4,
    CRIERR_FUNCTION_NOT_IMPLEMENTED = -5,
    CRIERR_LIBRARY_NOT_INITIALIZED = -6,
    CRIERR_ENUM_BE_SINT32 = 0x7FFFFFFF
} CriError;