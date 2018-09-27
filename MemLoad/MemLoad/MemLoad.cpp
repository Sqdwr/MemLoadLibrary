#include <iostream>
#include <windows.h>

using namespace std;

typedef BOOL(APIENTRY *DLLENTRY)(HMODULE hModule,ULONG ul_reason_for_call,LPVOID lpReserved);
typedef VOID(WINAPI *MSG_CALL)();

ULONG TurnRvaIntoRaw(PIMAGE_NT_HEADERS temp, ULONG_PTR Rva)
{
	ULONG NumbersOfSections = temp->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(temp);
	for (ULONG i = 0; i < NumbersOfSections; ++i)
	{
		ULONG StartAddress = SectionHeader->VirtualAddress;
		ULONG EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;
		if (Rva >= StartAddress && Rva <= EndAddress)
			return Rva - StartAddress + SectionHeader->PointerToRawData;
		++SectionHeader;
	}
	return 0;
}

PUCHAR GetFileContext()
{
	CHAR FileName[MAX_PATH];
	cout << "����DLL���ƣ�";
	cin.getline(FileName, sizeof(FileName));

	HANDLE hFile = CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		cout << "��<<" << FileName << "ʧ�ܣ�" << endl;
		cout << "�������ǣ�" << GetLastError() << endl;
		return NULL;
	}

	ULONG FileSize = GetFileSize(hFile, NULL);
	UCHAR *FileContent = (UCHAR*)VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (FileContent == NULL)
	{
		CloseHandle(hFile);
		cout << "�����ڴ�ʧ�ܣ�" << endl;
		cout << "�������ǣ�" << GetLastError() << endl;
		return NULL;
	}
	ZeroMemory(FileContent, FileSize);

	ULONG ReadFileSize = 0;
	BOOL bRead = ReadFile(hFile, FileContent, FileSize, &ReadFileSize, NULL);
	if (bRead == FALSE)
	{
		CloseHandle(hFile);
		VirtualFree(FileContent, 0, MEM_RELEASE);
		cout << "��ȡ�ļ�ʧ�ܣ�" << endl;
		cout << "�������ǣ�" << GetLastError() << endl;
		return NULL;
	}

	return FileContent;
}

BOOL LoadPE(UCHAR* FileContent)
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "DOSͷ��ƥ�䣡" << endl;
		return FALSE;
	}

	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "NTͷ��ƥ�䣡" << endl;
		return FALSE;
	}

	UCHAR *ImageBase = (UCHAR*)VirtualAlloc(NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (ImageBase == NULL)
	{
		cout << "�����ڴ�ʧ�ܣ�" << endl;
		cout << "�������ǣ�" << GetLastError() << endl;
		return FALSE;
	}
	ZeroMemory(ImageBase, NtHeader->OptionalHeader.SizeOfImage);
	memcpy(ImageBase, FileContent, NtHeader->OptionalHeader.SizeOfHeaders);				//����ͷ��

	/*�����ڴ��е����򿽱�����*/
	IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		memcpy(ImageBase + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

	/*���˸��ƺ������еĶ�����������Ҫ�ѵ�����滻��*/
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			HMODULE hModule = LoadLibraryA((CHAR *)(ImageBase + ImportDescriptor->Name));
			if (hModule == NULL)
			{
				cout << "LoadLibraryʧ�ܣ�" << endl;
				return FALSE;
			}

			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(ImageBase + ImportDescriptor->FirstThunk);
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)								//�����λΪ1����Ϊ������룬��������������
				{
					ThunkData->u1.Function = (ULONG)(GetProcAddress(hModule, (char*)(ThunkData->u1.Ordinal & 0x0000ffff)));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)(ImageBase + ThunkData->u1.AddressOfData);
					ThunkData->u1.Function = (ULONG)(GetProcAddress(hModule, ImportName->Name));
				}
			}
			FreeLibrary(hModule);
		}
	}

	/*���ˣ�������Ҳ�Ѿ��޸Ľ����ˣ�FirstThunk����ȫ�����Ǻ����ĵ�ַ�ˣ�������ʲô�����Ӱ˵Ĺ����ˡ�*/
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		//���ƫ�����ǵ�ǰPE���ڴ��е�ƫ�Ƽ�ȥPE�ļ�Ӧ�����صĻ�ַ��
		ULONG Offset = (ULONG)ImageBase - (ULONG)NtHeader->OptionalHeader.ImageBase;

		IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		for (; RelocationImage->VirtualAddress != 0;)
		{
			/*�������Ϊʲôд
			#define CountRelocationEntries(dwBlockSize)		\
			(dwBlockSize -								\
			sizeof(BASE_RELOCATION_BLOCK)) /			\
			sizeof(BASE_RELOCATION_ENTRY)
			�Ͳ鿴���*/
			ULONG NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			USHORT * Block = (USHORT *)((CHAR*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
			for (USHORT i = 0; i < NumberOfBlocks; ++i, Block++)
			{
				USHORT Addr = *Block & 0x0fff;											//�õ�12λ��Ϊ��־��
				USHORT Sign = *Block >> 12;												//����λ��Ϊ��־������
				if (Sign == 3)
				{
					ULONG AddressOffset = RelocationImage->VirtualAddress + Addr;				//Block�ǵ�ǰҳ���ڲ��ı��˵�ַ�����Լ��ϵ�ǰҳ���λ�ü�����ƫ�Ƶ�ַ��
					*(ULONG *)(ImageBase + AddressOffset) += Offset;									//��PE���ڴ����ҵ�Ҫ�ض�λ�ĵ�ַ��Ȼ��ѵ�ַ����ƫ��ɡ�������Ҫ��ǿ��ת����long���ͣ�����ռ���ĸ��ֽ�
				}
				else if (Sign == 0)
				{
					//signΪ0��ģ�������Ϊ�˶����ڴ档
				}
			}
			RelocationImage = (IMAGE_BASE_RELOCATION *)((char*)RelocationImage + RelocationImage->SizeOfBlock);
		}
	}

	IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	cout << "������������Ϊ��" << ExportDirectory->NumberOfFunctions << endl;

	ULONG* ExportNameArry = (ULONG*)(ImageBase + ExportDirectory->AddressOfNames);
	ULONG *ExportAddressArry = (ULONG*)(ImageBase + ExportDirectory->AddressOfFunctions);

	for (USHORT i = 0; i < ExportDirectory->NumberOfFunctions; ++i)
		cout << "��" << i + 1 << "������Ϊ��" << (CHAR*)(ImageBase + *ExportNameArry) << endl;
	MSG_CALL t = (MSG_CALL)(ImageBase + *ExportAddressArry);
	t();

	DLLENTRY Entry = (DLLENTRY)(ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint);
	Entry((HMODULE)ImageBase, DLL_PROCESS_ATTACH, 0);

	//�������������ImageBase�����ͷţ��ͷŽ����˳���ʱ��ͻ����
	//VirtualFree(ImageBase, 0, MEM_RELEASE);

	return TRUE;
}

int main()
{
	INT RetValue = 0;;
	UCHAR *FileContent = NULL;
	do 
	{
		FileContent = GetFileContext();
		if (FileContent == NULL)
		{
			RetValue = -1;
			break;
		}

		BOOL bLoad = LoadPE(FileContent);
		if (bLoad == FALSE)
		{
			RetValue = -1;
			break;
		}
	} while (FALSE);

	VirtualFree(FileContent, 0, MEM_RELEASE);

	system("pause");
	return RetValue;
}