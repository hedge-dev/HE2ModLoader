#pragma once
#include <SigScanner.h>

class SignatureScanner
{
public:
	static bool MemoryCompare(const char* data, const char* sig, const char* mask)
	{
		for (; *mask; ++mask, ++data, ++sig)
			if (*mask == 'x' && *data != *sig)
				return false;
		return (*mask == NULL);
	}

	static size_t FindSignature(size_t start, size_t size, const char* sig, const char* mask)
	{
		return reinterpret_cast<size_t>(CommonLoader::Scan(sig, mask, strlen(mask), reinterpret_cast<void*>(start), size));
	}
};