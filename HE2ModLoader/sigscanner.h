#pragma once

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
		char* data = (char*)start;

		for (size_t i = 0; i < size; i++)
			if (MemoryCompare((const char*)(data + i), (const char*)sig, mask))
				return start + i;
		return NULL;
	}
};