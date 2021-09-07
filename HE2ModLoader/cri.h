#pragma once

// Types
typedef char CriChar8;
typedef signed int CriSint32;
typedef unsigned int CriUint32;
typedef unsigned int* CriUintPtr;
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

// Functions
void InitLoaderCri();
