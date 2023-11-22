#pragma once

struct EOS_InitializeOptions
{
    int apiVersion;
    void* allocateMemoryFunction;
    void* reallocateMemoryFunction;
    void* releaseMemoryFunction;
    const char* productName;
    const char* productVersion;
    void* reserved;
    void* systemInitializeOptions;
    void* overrideThreadAffinity;
};
