// #define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <cassert>

#pragma comment(lib, "crypt32.lib")

static LPCSTR inFileName = "input.txt";
static LPCSTR outFileName = "output.txt";

static long FileSize(FILE* f)
{
	fseek(f, 0L, SEEK_END);
	long res = ftell(f);
	rewind(f);
	return res;
}

static void IncorrectUsage()
{
	printf("Usage: {en | de} [[inFile]] [[outFile]]\n\n");

	printf(" en       For encrypt.\n");
	printf(" de       For decrypt.\n");
	printf(" inFile   Path to the input file.\n");
	printf(" outFile  Path to the output file.\n");

	exit(1);
}

int main(int argc, char** argv)
{
	char action[MAX_PATH] = { 0 };

	if (argc == 1)
	{
		do
		{
			printf("Encrypt = \"en\"; decrypt = \"de\": ");
			scanf_s("%s", action, (DWORD)_countof(action));
		} while (strcmp(action, "en") && strcmp(action, "de"));
	}
	else if (argc <= 4)
	{
		if (argc >= 2)
		{
			strcpy_s(action, sizeof(action), argv[1]);
			if (strcmp(action, "en") && strcmp(action, "de"))
			{
				IncorrectUsage();
			}
		}

		if (argc >= 3)
		{
			inFileName = argv[2];
		}

		if (argc >= 4)
		{
			outFileName = argv[3];
		}
	}
	else
	{
		IncorrectUsage();
	}

	DATA_BLOB DataIn = { 0, NULL };
	DATA_BLOB DataOut = { 0, NULL };

	FILE* fin;
	fopen_s(&fin, inFileName, "rb");
	if (!fin)
	{
		printf("Failed to open file \"%s\".\n", inFileName);
		exit(1);
	}

	DWORD finSz = FileSize(fin);

	BYTE* inBuf = (BYTE*)malloc(finSz);
	fread_s(inBuf, finSz, finSz, 1, fin);
	fclose(fin);

	DataIn.cbData = finSz;
	DataIn.pbData = (BYTE*)malloc(DataIn.cbData);
	memcpy_s(DataIn.pbData, finSz, inBuf, finSz);

	typedef BOOL(__stdcall* SyscallFn)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
	SyscallFn syscall = !strcmp(action, "en") ? (SyscallFn)CryptProtectData : (SyscallFn)CryptUnprotectData;

	if (syscall(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut))
	{
		printf("Successfully %scrypted.\n", action);
	}
	else
	{
		printf("Unsuccessfully %scrypted.\n", action);
		printf("ErrorCode = %u.\n", GetLastError());

		if (GetLastError() == 13)
		{
			printf("Invalid data.\n");
			printf("Probably the file have been corrupted.\n");
		}

		return 1;
	}

	FILE* fout;
	fopen_s(&fout, outFileName, "wb");
	if (!fout)
	{
		printf("The output file cannot be opened for writing.");
		return 1;
	}

	fwrite(DataOut.pbData, DataOut.cbData, 1, fout);
	fclose(fout);
	LocalFree(DataOut.pbData);

	printf("Written to file successfully.\n");

	return 0;
}
