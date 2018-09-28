#include <iostream>
#include <windows.h>

using namespace std;

typedef BOOL(APIENTRY *DLLENTRY)(HMODULE hModule,ULONG_PTR ul_reason_for_call,LPVOID lpReserved);
typedef VOID(WINAPI *MSG_CALL)();

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

ULONG_PTR TurnRvaIntoRaw(PIMAGE_NT_HEADERS temp, ULONG_PTR Rva)
{
	ULONG_PTR NumbersOfSections = temp->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(temp);
	for (ULONG_PTR i = 0; i < NumbersOfSections; ++i)
	{
		ULONG_PTR StartAddress = SectionHeader->VirtualAddress;
		ULONG_PTR EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;
		if (Rva >= StartAddress && Rva <= EndAddress)
			return Rva - StartAddress + SectionHeader->PointerToRawData;
		++SectionHeader;
	}
	return 0;
}

PUCHAR GetFileContext()
{
	CHAR FileName[MAX_PATH];
	cout << "输入DLL名称：";
	cin.getline(FileName, sizeof(FileName));

	HANDLE hFile = CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		cout << "打开<<" << FileName << "失败！" << endl;
		cout << "错误码是：" << GetLastError() << endl;
		return NULL;
	}

	ULONG FileSize = GetFileSize(hFile, NULL);
	UCHAR *FileContent = (UCHAR*)VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (FileContent == NULL)
	{
		CloseHandle(hFile);
		cout << "分配内存失败！" << endl;
		cout << "错误码是：" << GetLastError() << endl;
		return NULL;
	}
	ZeroMemory(FileContent, FileSize);

	ULONG ReadFileSize = 0;
	BOOL bRead = ReadFile(hFile, FileContent, FileSize, &ReadFileSize, NULL);
	if (bRead == FALSE)
	{
		CloseHandle(hFile);
		VirtualFree(FileContent, 0, MEM_RELEASE);
		cout << "读取文件失败！" << endl;
		cout << "错误码是：" << GetLastError() << endl;
		return NULL;
	}

	return FileContent;
}

BOOL LoadPE(UCHAR* FileContent)
{
	IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)FileContent;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "DOS头不匹配！" << endl;
		return FALSE;
	}

	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "NT头不匹配！" << endl;
		return FALSE;
	}

	UCHAR *ImageBase = (UCHAR*)VirtualAlloc(NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (ImageBase == NULL)
	{
		cout << "分配内存失败！" << endl;
		cout << "错误码是：" << GetLastError() << endl;
		return FALSE;
	}
	ZeroMemory(ImageBase, NtHeader->OptionalHeader.SizeOfImage);
	memcpy(ImageBase, FileContent, NtHeader->OptionalHeader.SizeOfHeaders);				//拷贝头部

	/*按照内存中的排序拷贝区块*/
	IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
		memcpy(ImageBase + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

	/*至此复制好了所有的东西，下面需要把导入表替换了*/
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; ImportDescriptor->Name != NULL; ++ImportDescriptor)
		{
			HMODULE hModule = LoadLibraryA((CHAR *)(ImageBase + ImportDescriptor->Name));
			if (hModule == NULL)
			{
				cout << "LoadLibrary失败！" << endl;
				return FALSE;
			}

			IMAGE_THUNK_DATA *ThunkData = (IMAGE_THUNK_DATA *)(ImageBase + ImportDescriptor->FirstThunk);
			for (; ThunkData->u1.Ordinal != 0; ThunkData++)
			{
				if (ThunkData->u1.Ordinal & 0x80000000)								//如果首位为1则是为序号输入，否则是姓名输入
				{
					ThunkData->u1.Function = (ULONG_PTR)(GetProcAddress(hModule, (char*)(ThunkData->u1.Ordinal & 0x0000ffff)));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)(ImageBase + ThunkData->u1.AddressOfData);
					ThunkData->u1.Function = (ULONG_PTR)(GetProcAddress(hModule, ImportName->Name));
				}
			}
			FreeLibrary(hModule);
		}
	}

	/*好了，如今导入表也已经修改结束了，FirstThunk里面全部都是函数的地址了，不再是什么杂七杂八的鬼东西了。*/
	if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		//这个偏移量是当前PE在内存中的偏移减去PE文件应当加载的基址。
		ULONG_PTR Offset = (ULONG_PTR)ImageBase - (ULONG_PTR)NtHeader->OptionalHeader.ImageBase;

		IMAGE_BASE_RELOCATION *RelocationImage = (IMAGE_BASE_RELOCATION *)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		for (; RelocationImage->VirtualAddress != 0;)
		{
			/*这里具体为什么写，是因为最前面有一个IMAGE_BASE_RELOCATION，然后紧接着的是N个2字节的Block*/
			ULONG_PTR NumberOfBlocks = (RelocationImage->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
			BASE_RELOCATION_ENTRY * Block = (BASE_RELOCATION_ENTRY *)((CHAR*)RelocationImage + sizeof(IMAGE_BASE_RELOCATION));
			for (USHORT i = 0; i < NumberOfBlocks; ++i, Block++)
			{
				USHORT Addr = Block->Offset;														//用低12位作为标志。
				USHORT Sign = Block->Type;															//高四位作为标志来运算
				if (Sign == IMAGE_REL_BASED_HIGHLOW)
				{
					ULONG_PTR AddressOffset = RelocationImage->VirtualAddress + Addr;				//Block是当前页面内部的便宜地址，所以加上当前页面的位置即是总偏移地址。
					*(ULONG_PTR *)(ImageBase + AddressOffset) += Offset;							//在PE的内存中找到要重定位的地址，然后把地址加上偏差即可。这里需要先强制转化成long类型，让他占用四个字节
				}
				else if (Sign == IMAGE_REL_BASED_ABSOLUTE)
				{
					//sign为0的模块仅仅是为了对齐内存。
				}
				else if (Sign == IMAGE_REL_BASED_DIR64)												//这个值是专门在64位可执行文件上使用的类型
				{
					ULONG_PTR AddressOffset = RelocationImage->VirtualAddress + Addr;				//Block是当前页面内部的便宜地址，所以加上当前页面的位置即是总偏移地址。
					*(ULONG_PTR *)(ImageBase + AddressOffset) += Offset;							//在PE的内存中找到要重定位的地址，然后把地址加上偏差即可。这里需要先强制转化成long类型，让他占用四个字节
				}
			}
			RelocationImage = (IMAGE_BASE_RELOCATION *)((char*)RelocationImage + RelocationImage->SizeOfBlock);
		}
	}

	IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(ImageBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	cout << "导出函数总数为：" << ExportDirectory->NumberOfFunctions << endl;

	ULONG* ExportNameArry = (ULONG*)(ImageBase + ExportDirectory->AddressOfNames);
	ULONG *ExportAddressArry = (ULONG*)(ImageBase + ExportDirectory->AddressOfFunctions);

	for (USHORT i = 0; i < ExportDirectory->NumberOfFunctions; ++i)
		cout << "第" << i + 1 << "个函数为：" << (CHAR*)(ImageBase + *ExportNameArry) << endl;
	MSG_CALL t = (MSG_CALL)(ImageBase + *ExportAddressArry);
	t();

	DLLENTRY Entry = (DLLENTRY)(ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint);
	Entry((HMODULE)ImageBase, DLL_PROCESS_ATTACH, 0);

	//不明觉厉，这个ImageBase不能释放，释放进程退出的时候就会崩掉
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
