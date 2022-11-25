#include "pch.h"
#include "criAudio.h"
#include "helpers.h"
#include "sigscanner.h"
#include <mutex>
#include <algorithm>

std::unordered_map<HANDLE, std::shared_ptr<CriAudio>> CriAudios;
std::unordered_map<HANDLE, std::shared_ptr<CriACBPatcher>> CriACBPatchers;

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

void CriAudio::ParseAFS2Archive(string filePath)
{
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
	subkey = ReadUInt16(file);

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
		streamList[i].fileOffset = (streamList[i].fileOffset + alignment - 1) & ~(alignment - 1);
		if (i == streamCount - 1)
			streamList[i].fileSize = (addressSize == 2 ? ReadUInt16(file) : ReadUInt32(file)) - streamList[i].fileOffset;
		if (i != 0)
			streamList[i - 1].fileSize = streamList[i].fileOffset - streamList[i - 1].fileOffset;
	}
	fclose(file);
}

int CriAudio::GenerateHeader()
{
	char* oldBuffer = header;
	char* buffer = header;
	// Header
	*(unsigned int*)(buffer + 0)    = 0x32534641;
	*(unsigned char*)(buffer + 4)   = 0x02;
	*(unsigned char*)(buffer + 5)   = 0x04;
	*(unsigned short*)(buffer + 6)  = 0x02;
	*(unsigned int*)(buffer + 8)    = streamList.size();
	*(unsigned short*)(buffer + 12) = 0x20;
	*(unsigned short*)(buffer + 14) = subkey;

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
		address = (address + 31) & ~31;
		*(unsigned int*)(buffer) = address;
		stream.emulatedAddress = address;
		buffer += 4;
		address += stream.fileSize;
	}
	*(unsigned int*)(buffer) = address;
	buffer += 4;

	int headerSize = (int)(buffer - oldBuffer);

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

const string& CriAudio::GetName() const
{
	return basePath;
}

const vector<CriAudioStream>& CriAudio::GetStreams() const
{
	return streamList;
}

void CriAudio::ReplaceAudio(int id, HANDLE hcaHandle)
{
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

HANDLE CriAudio::GetAWBHandle() const
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

// TODO: Look into why streams sometimes don't play
bool CriAudio::ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer, ReadFileType readFile)
{
	// Read streams
	for (auto& stream : streamList)
	{
		if (awbPosition == stream.emulatedAddress)
			PrintDebug("Loading stream %d from %s", stream.id, basePath.c_str());
		if (awbPosition >= stream.emulatedAddress && awbPosition < stream.emulatedAddress + stream.fileSize)
		{
			unsigned int offset = awbPosition - stream.emulatedAddress;
			HANDLE handle = stream.fileHandle;
			SetFilePointer(handle, stream.fileOffset + offset, NULL, FILE_BEGIN);
			return readFile(handle, buffer, size, bytesRead, NULL);
		}
	}
	return false;
}

CriAudio::CriAudio(string path, HANDLE handle)
{
	basePath = path;
	memset(header, 0, sizeof(header));
	ParseAFS2Archive(path + ".awb");
	SetAWBHandle(handle);
}

CriAudio::~CriAudio()
{
	// Close replaced handles
	for (auto& stream : streamList)
	{
		if (stream.fileHandle != awbHandle)
			CloseHandle(stream.fileHandle);
	}
}

CriACBPatcher::CriACBPatcher(string path, HANDLE handle)
{
	basePath = path;
	awbHeaderPosition = -1;
	embeddedAwbPosition = -1;
	memset(awbHeader, 0, sizeof(awbHeader));
	SetHandle(handle);
	ParseACBFile();
}

// TODO: Actually parse the ACB file
void CriACBPatcher::ParseACBFile()
{
	// Please don't do this
	int fileSize = GetFileSize(handle, nullptr);
	auto buffer_ptr = std::unique_ptr<char[]>(new char[fileSize] {});
	char* buffer = buffer_ptr.get();
	SetFilePointer(handle, 0, NULL, FILE_BEGIN);

	if (ReadFile(handle, buffer, fileSize, nullptr, nullptr))
	{
		SetFilePointer(handle, 0, NULL, FILE_BEGIN);

		// Get AWB header position
		char pattern[] = { 0x53, 0x74, 0x72, 0x65, 0x61, 0x6D, 0x41, 0x77, 0x62, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72 }; // StreamAwbHeader

		char* scanPos = std::search(buffer, buffer + fileSize, pattern, pattern + sizeof(pattern));

		if (scanPos != buffer + fileSize)
			awbHeaderPosition = (LONG)(scanPos - buffer + 0x17);
		else
			return; // Exit if no header is found

		// Get Embedded AWB
		char pattern2[] = { 0x41, 0x46, 0x53, 0x32, 0x02, 0x04 }; // AFS2\x02\x04

		scanPos = std::search(buffer, buffer + fileSize, pattern2, pattern2 + sizeof(pattern2));

		if (scanPos != buffer + fileSize && scanPos != (buffer + awbHeaderPosition))
		{
			embeddedAwbPosition = (LONG)(scanPos - buffer);
			int trackCount = *(int*)(scanPos + 0x08);
			for (int i = 0; i < trackCount; ++i)
			{
				CriAudioTrack track;
				track.id = *(int*)(scanPos + 0x10 + i * 0x02);
				track.offset = *(int*)(scanPos + 0x10 + trackCount * 0x02 + i * 0x04);
				track.offset = (track.offset + 31) & ~31; // Apply padding
				track.size = *(int*)(scanPos + 0x10 + trackCount * 0x02 + (i + 1) * 0x04) - track.offset; // Usually 0x1460

				char* address = scanPos + track.offset;
				memcpy(track.data, address, track.size);

				embeddedAwbTracks.push_back(track);
			}
		}
	}
}

void CriACBPatcher::LoadCriAudio(CriAudio* audio)
{
	awbHeaderSize = audio->GetHeaderSize();
	memcpy(awbHeader, audio->GetHeader(), awbHeaderSize);

	// Load custom tracks
	for (CriAudioTrack& track : embeddedAwbTracks)
	{
		for (const CriAudioStream& stream : audio->GetStreams())
		{
			if (track.id == stream.id && stream.fileHandle != audio->GetAWBHandle())
			{
				PrintDebug("Reading stream %d for ACB injection", stream.id);
				SetFilePointer(stream.fileHandle, 0, NULL, FILE_BEGIN);
				if (ReadFile(stream.fileHandle, track.data, track.size, nullptr, NULL))
					SetFilePointer(stream.fileHandle, 0, NULL, FILE_BEGIN);
			}
		}
	}
}

void CriACBPatcher::SetHandle(HANDLE hnd)
{
	handle = hnd;
}

HANDLE CriACBPatcher::GetHandle() const
{
	return handle;
}

void CriACBPatcher::SetPosition(LONG position, bool relative)
{
	if (relative)
		currentPosition += position;
	else
		currentPosition = position;
}

bool CriACBPatcher::ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer)
{
	// Inject embedded AWB
	if (embeddedAwbPosition >= currentPosition)
	{
		for (CriAudioTrack& track : embeddedAwbTracks)
		{
			if (embeddedAwbPosition + track.offset + track.size <= currentPosition + size)
			{
				int offset = (embeddedAwbPosition + track.offset) - currentPosition;
				memcpy(((char*)buffer) + offset, track.data, track.size);
			}
		}
	}

	// Inject AWB header
	if (awbHeaderPosition >= currentPosition && awbHeaderPosition + awbHeaderSize < currentPosition + size)
	{
		int offset = awbHeaderPosition - currentPosition;
		memcpy(((char*)buffer) + offset, awbHeader, awbHeaderSize);

		return true;
	}
	return false;
}


HOOK(BOOL, __fastcall, Kernel32SetFilePointer, PROC_ADDRESS("Kernel32.dll", "SetFilePointer"), HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
	const auto pairAWB = CriAudios.find(hFile);
	const auto pairACB = CriACBPatchers.find(hFile);
	if (pairAWB != CriAudios.end())
		pairAWB->second->SetAWBPosition(lDistanceToMove, dwMoveMethod == FILE_CURRENT);
	if (pairACB != CriACBPatchers.end())
		pairACB->second->SetPosition(lDistanceToMove, dwMoveMethod == FILE_CURRENT);

	return originalKernel32SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

HOOK(BOOL, __fastcall, Kernel32ReadFile, PROC_ADDRESS("Kernel32.dll", "ReadFile"), HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	const auto pairAWB = CriAudios.find(hFile);
	const auto pairACB = CriACBPatchers.find(hFile);
	if (pairAWB != CriAudios.end())
	{
		bool result = pairAWB->second->ReadData(nNumberOfBytesToRead, lpNumberOfBytesRead, lpBuffer, originalKernel32ReadFile);
		if (result)
		{
			SetFilePointer(hFile, nNumberOfBytesToRead, NULL, FILE_CURRENT);
			return true;
		}
	}
	if (pairACB != CriACBPatchers.end())
	{
		bool result = originalKernel32ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
		if (result)
			pairACB->second->ReadData(nNumberOfBytesToRead, lpNumberOfBytesRead, lpBuffer);
		return result;
	}
	return originalKernel32ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

std::mutex mutex;

HOOK(BOOL, __fastcall, Kernel32CloseHandle, PROC_ADDRESS("Kernel32.dll", "CloseHandle"), HANDLE handle)
{
	CriAudios.erase(handle);
	CriACBPatchers.erase(handle);
	return originalKernel32CloseHandle(handle);
}

void InitCriAudio()
{
	INSTALL_HOOK(Kernel32ReadFile);
	INSTALL_HOOK(Kernel32SetFilePointer);
	INSTALL_HOOK(Kernel32CloseHandle);
}