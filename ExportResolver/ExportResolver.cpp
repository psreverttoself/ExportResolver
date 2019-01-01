#include <Windows.h>
#include <winternl.h>

typedef void* (*_MyLoadLibraryA) (const char*);
typedef void* (*_MyGetProcAddress) (void*, const char*);
typedef int(*_MyMessageBoxA) (void*, const char*, const char*, unsigned int);

int StringCompareA(const char* string1, const char* string2)
{
	int index = 0;

	while (1)
	{
		if (string1[index] == 0 && string2[index] == 0) return 1;
		if (string1[index] == 0 || string2[index] == 0) return 0;
		if (string1[index] != string2[index]) return 0;

		index++;
	}
}

PEB* GetPebAddress()
{
	PEB* result;
	TEB* teb;
#ifdef _WIN64
	teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
	teb = (TEB*)__readfsdword(0x18);
#endif 

	result = teb->ProcessEnvironmentBlock;

	return result;
}

void* GetFunctionAddress(const char* moduleName, const char* funcName)
{
	PEB* peb = GetPebAddress();

	LDR_DATA_TABLE_ENTRY* firstEntryAddr = (LDR_DATA_TABLE_ENTRY*)(((char*)peb->Ldr->InMemoryOrderModuleList.Flink) - sizeof(void*) * 2);
	LDR_DATA_TABLE_ENTRY* currentEntryAddr = firstEntryAddr;
	IMAGE_DOS_HEADER* dosHeader = 0;
	IMAGE_DATA_DIRECTORY* ddExport = 0;
	IMAGE_EXPORT_DIRECTORY* exportDirectory = 0;

	do
	{
		currentEntryAddr = (LDR_DATA_TABLE_ENTRY*)(((char*)currentEntryAddr->InMemoryOrderLinks.Flink) - sizeof(void*) * 2);

		dosHeader = (IMAGE_DOS_HEADER*)currentEntryAddr->DllBase;

		if (!dosHeader) continue;

		if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
#ifdef _WIN64
			IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(((char*)dosHeader) + dosHeader->e_lfanew);

			if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
			{
				IMAGE_OPTIONAL_HEADER64* optionalHeader = &ntHeaders->OptionalHeader;

				if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				{
					ddExport = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

					exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(((char*)dosHeader) + ddExport->VirtualAddress);
				}
			}
#elif _WIN32
			IMAGE_NT_HEADERS32* ntHeaders = (IMAGE_NT_HEADERS32*)(((char*)dosHeader) + dosHeader->e_lfanew);

			if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
			{
				IMAGE_OPTIONAL_HEADER32* optionalHeader = &ntHeaders->OptionalHeader;

				if (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					ddExport = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

					exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(((char*)dosHeader) + ddExport->VirtualAddress);
				}
			}
#endif 
			char* dllName = (char*)(((char*)dosHeader) + exportDirectory->Name);

			if (!StringCompareA(dllName, moduleName)) continue;

			int* nameOffsets = (int*)(((char*)dosHeader) + exportDirectory->AddressOfNames);
			short* ordinalOffsets = (short*)(((char*)dosHeader) + exportDirectory->AddressOfNameOrdinals);
			int* functionOffsets = (int*)(((char*)dosHeader) + exportDirectory->AddressOfFunctions);

			for (int i = 0; i < exportDirectory->NumberOfNames; i++)
			{
				char* functionName = (char*)(((char*)dosHeader) + nameOffsets[i]);

				if (StringCompareA(functionName, funcName))
				{
					short ordinal = ordinalOffsets[i];
					void* funcAddress = (((char*)dosHeader) + functionOffsets[ordinal]);

					return funcAddress;
				}
			}
		}


	} while (currentEntryAddr != firstEntryAddr);

	return 0;
}

int Main()
{
	_MyLoadLibraryA MyLoadLibraryA = (_MyLoadLibraryA)GetFunctionAddress("KERNEL32.dll", "LoadLibraryA");
	_MyGetProcAddress MyGetProcAddress = (_MyGetProcAddress)GetFunctionAddress("KERNEL32.dll", "GetProcAddress");

	void* user32 = MyLoadLibraryA("user32.dll");

	_MyMessageBoxA MyMessageBoxA = (_MyMessageBoxA)MyGetProcAddress(user32, "MessageBoxA");

	MyMessageBoxA(0, "Demo", "Message", MB_OK);
	return 0;
}