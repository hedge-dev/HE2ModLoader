#include "pch.h"
#include "criAudio.h"
#include "helpers.h"
#include "sigscanner.h"

std::unordered_map<string, CriAudio*> CriAudios;

void SeekForward(FILE* handle, long amount)
{
	fseek(handle, amount, SEEK_CUR);
}

unsigned short ReadUInt8(FILE* handle)
{
	unsigned short data = 0;
	fread(&data, 1, 1, handle);
	return data;
}

unsigned short ReadUInt16(FILE* handle)
{
	unsigned short data;
	fread(&data, 2, 1, handle);
	return data;
}

unsigned int ReadUInt32(FILE* handle)
{
	unsigned int data;
	fread(&data, 4, 1, handle);
	return data;
}

CriAudio* GetCriAudioByName(string basePath)
{
	if (CriAudios.find(basePath) == CriAudios.end())
		return nullptr;

	return CriAudios[basePath];
}

void CriAudio::ParseAFS2Archive(string filePath)
{
	PrintDebug("Parsing AFS2 archive for %s", filePath.c_str());
	// Open file
	FILE* file;
	fopen_s(&file, filePath.c_str(), "rb");
	if (!file)
		return;

	// Check signature
	if (ReadUInt32(file) != 0x32534641)
	{
		PrintError("Invalid AFS2 signature found!");
		return;
	}
	SeekForward(file, 1);						 // Skip version
	unsigned short addressSize = ReadUInt8(file);
	SeekForward(file, 2);						 // Skip again
	unsigned int streamCount = ReadUInt32(file);
	unsigned short alignment = ReadUInt16(file);
	SeekForward(file, 2);					     // Skip subkey

	// Read stream IDs
	for (int i = 0; i < streamCount; ++i)
	{
		CriAudioStream stream {};
		stream.id = ReadUInt16(file);
		streamList.push_back(stream);
	}

	// Read stream addresses
	for (int i = 0; i < streamCount; ++i)
	{
		streamList[i].fileOffset = addressSize == 2 ? ReadUInt16(file) : ReadUInt32(file);
		if (i == streamCount - 1)
			streamList[i].fileSize = (addressSize == 2 ? ReadUInt16(file) : ReadUInt32(file)) - streamList[i].fileOffset;
		if (i != 0)
			streamList[i - 1].fileSize = streamList[i].fileOffset - streamList[i - 1].fileOffset;
	}
	fclose(file);
}

int CriAudio::GenerateHeader()
{
	PrintDebug("Generating header for %s", basePath.c_str());
	char* oldBuffer = header;
	char* buffer = header;
	// Header
	*(unsigned int*)(buffer + 0)    = 0x32534641;
	*(unsigned char*)(buffer + 4)   = 0x02;
	*(unsigned char*)(buffer + 5)   = 0x04;
	*(unsigned short*)(buffer + 6)  = 0x02;
	*(unsigned int*)(buffer + 8)    = streamList.size();
	*(unsigned short*)(buffer + 12) = 0x20;
	*(unsigned short*)(buffer + 14) = 0x0000;

	// Save position
	buffer += 16;

	// IDs
	for (auto& stream : streamList)
	{
		*(unsigned short*)(buffer) = stream.id;
		buffer += 2;
	}

	// Offsets
	int address = 0x10 + streamList.size() * 6 + 4;
	for (auto& stream : streamList)
	{
		*(unsigned int*)(buffer) = stream.emulatedAddress = address;
		buffer += 4;
		address += stream.fileSize;
	}
	*(unsigned int*)(buffer) = address;
	buffer += 4;

	int headerSize = (int)(buffer - oldBuffer);
	// Padding
	headerSize += 0x20 - (headerSize % 0x20);

	return headerSize;
}

void* CriAudio::GetHeader()
{
	if (!header[0])
		headerSize = GenerateHeader();
	return header;
}

int CriAudio::GetHeaderSize()
{
	if (!header[0])
		return GenerateHeader();
	return headerSize;
}

vector<CriAudioStream> CriAudio::GetStreams()
{
	return streamList;
}

void CriAudio::ReplaceAudio(int id, HANDLE hcaHandle)
{
	PrintDebug("Replacing audio ID %d for %s", id, basePath.c_str());

	streamList[id].fileHandle = hcaHandle;
	streamList[id].fileOffset = 0;
	streamList[id].fileSize = GetFileSize(hcaHandle, NULL);
}

void CriAudio::SetAWBHandle(HANDLE handle)
{
	awbHandle = handle;

	// Link existing streams
	for (auto& stream : streamList)
	{
		if (stream.fileOffset != 0)
			stream.fileHandle = handle;
	}
}

HANDLE CriAudio::GetAWBHandle()
{
	return awbHandle;
}

void CriAudio::SetAWBPosition(LONG position, bool relative)
{
	if (relative)
		awbPosition += position;
	else
		awbPosition = position;
}

bool CriAudio::ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer)
{
	// Read header
	if (awbPosition < headerSize)
	{
		if (size > headerSize - awbPosition)
			*bytesRead = headerSize - awbPosition;
		else
			*bytesRead = size;
		memcpy(buffer, header, *bytesRead);
		awbPosition += *bytesRead;
	}
	// Read streams
	for (auto& stream : streamList)
	{
		if (awbPosition == stream.emulatedAddress)
			PrintDebug("Loading stream %d from %s", stream.id, basePath.c_str());
		if (awbPosition >= stream.emulatedAddress && awbPosition + size < stream.emulatedAddress + stream.fileSize)
		{
			unsigned int offset = awbPosition - stream.emulatedAddress;
			HANDLE handle = stream.fileHandle;
			if (handle == awbHandle)
				handle = mainAwbHandle;
			SetFilePointer(handle, stream.fileOffset + offset, NULL, FILE_BEGIN);
			return ReadFile(handle, buffer, size, bytesRead, NULL);
		}
	}
	return false;
}

CriAudio::CriAudio(string path)
{
	basePath = path;
	memset(header, 0, sizeof(header));
	ParseAFS2Archive(path + ".awb");
	mainAwbHandle = CreateFileA((path + ".awb").c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	CriAudios[path] = this;
}

CriAudio::~CriAudio()
{
	CriAudios.erase(basePath);
}

HOOK(BOOL, __fastcall, Kernel32SetFilePointer, PROC_ADDRESS("Kernel32.dll", "SetFilePointer"), HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
	for (auto& criAudio : CriAudios)
	{
		if (hFile == criAudio.second->GetAWBHandle())
			criAudio.second->SetAWBPosition(lDistanceToMove, dwMoveMethod == FILE_CURRENT);
	}

	return originalKernel32SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

HOOK(BOOL, __fastcall, Kernel32ReadFile, PROC_ADDRESS("Kernel32.dll", "ReadFile"), HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	for (auto& criAudio : CriAudios)
	{
		if (hFile == criAudio.second->GetAWBHandle())
		{
			bool result = criAudio.second->ReadData(nNumberOfBytesToRead, lpNumberOfBytesRead, lpBuffer);
			SetFilePointer(hFile, nNumberOfBytesToRead, NULL, FILE_CURRENT);
			return result;
		}
	}
	return originalKernel32ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

HOOK(BOOL, __fastcall, Kernel32CloseHandle, PROC_ADDRESS("Kernel32.dll", "CloseHandle"), HANDLE handle)
{
	for (auto& criAudio : CriAudios)
	{
		if (handle == criAudio.second->GetAWBHandle())
		{
			criAudio.second->SetAWBHandle(nullptr);
			break;
		}
	}
	return originalKernel32CloseHandle(handle);
}


void InitCriAudio()
{
	INSTALL_HOOK(Kernel32ReadFile);
	INSTALL_HOOK(Kernel32SetFilePointer);
	INSTALL_HOOK(Kernel32CloseHandle);
}