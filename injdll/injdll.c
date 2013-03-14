//
//  injdll.c
//
//	Simple commandline DLL injection
//
//  www.catch22.net
//
//  Copyright (C) 2012 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <tlhelp32.h>

#define INJECT_PERMISSIONS (PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ)
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))


//
//	Enable/Disable privilege with specified name (for current process)
//
BOOL EnablePrivilege(TCHAR *szPrivName, BOOL fEnable)
{
	TOKEN_PRIVILEGES tp;
	LUID	luid;
	HANDLE	hToken;

	if(!LookupPrivilegeValue(NULL, szPrivName, &luid))
		return FALSE;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	
	tp.PrivilegeCount			= 1;
	tp.Privileges[0].Luid		= luid;
	tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
	
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	CloseHandle(hToken);

	return (GetLastError() == ERROR_SUCCESS);
}


BOOL EnableDebugPrivilege()
{
	return EnablePrivilege(SE_DEBUG_NAME, TRUE);
}

//
//	Get the process ID of the specified process
//
DWORD Process2Pid(const TCHAR *name)
{
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	HANDLE hSnapshot;
	DWORD  pid = 0;
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Error creating process list [%x]\n", GetLastError());
		return 0;
	}

	if(hSnapshot != INVALID_HANDLE_VALUE && Process32First(hSnapshot, &pe32))
	{
		do
		{
			if(lstrcmpi(pe32.szExeFile, name) == 0)
			{
				pid = pe32.th32ProcessID;
				break;
			}

		} while(Process32Next(hSnapshot, &pe32));

		CloseHandle(hSnapshot);
	}

	return pid;
}

//
//	Get the base address of the specified DLL in target process
//
DWORD_PTR ModuleBase(DWORD pid, TCHAR *szPath)
{
	MODULEENTRY32 me32 = { sizeof(me32) };
	HANDLE hSnapshot;
	DWORD_PTR base = 0;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32|TH32CS_SNAPMODULE, pid);

	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Error creating module list [%x]\n", GetLastError());
		return 0;
	}

	if(Module32First(hSnapshot, &me32))
	{
		do
		{
			if(szPath)
			{
				if(lstrcmpi(me32.szExePath, szPath) == 0)
				{
					base = (DWORD_PTR)me32.modBaseAddr;
					break;
				}
			}
			else
			{
				printf(" %08x  %ls\n", (DWORD_PTR)me32.modBaseAddr, me32.szExePath);
			}

		} while(Module32Next(hSnapshot, &me32));

		CloseHandle(hSnapshot);
	}

	return base;
}

//
//	Copy the specified buffer into the target process,
//  and return a pointer to the allocated buffer
//
PVOID copy_remote(HANDLE hProcess, PVOID buf, size_t len)
{
	PVOID remote = VirtualAllocEx(hProcess, 0, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if(remote == 0)
	{
		printf("Failed to alloc [%x]\n", GetLastError());
		return 0;
	}

	if(!WriteProcessMemory(hProcess, remote, buf, len, 0))
	{
		printf("Failed to write [%x]\n", GetLastError());
		VirtualFreeEx(hProcess, remote, len, MEM_RELEASE);
		return 0;
	}

	return remote;
}

//
//	Load a DLL into the target process
//
int load(int pid, TCHAR *path)
{
	PVOID  pRemotePath;
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  result = 0;
	size_t len;

	printf("Loading: %ls\n", path);
	
	hProcess = OpenProcess(INJECT_PERMISSIONS, FALSE, pid);

	if(hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Failed to OpenProcess [%x]\n", GetLastError());
		return 0;
	}

	len = (_tcslen(path)+1) * sizeof(TCHAR);
	if((pRemotePath = copy_remote(hProcess, path, len)) == 0)
	{
		return 0;
	}

#ifdef UNICODE
	hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, pRemotePath, 0, 0);
#else
	hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemotePath, 0, 0);
#endif

	if(hThread == 0)
	{
		printf("Failed to load library [%x]\n", GetLastError());
		return 0;
	}

	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &result);

	printf("LoadLibrary: 0x%x\n", result);
	
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemotePath, len, MEM_RELEASE);
	CloseHandle(hProcess);

	return 1;
}

//
//	Free the specified DLL in target process
//
int unload(int pid, TCHAR *szPath)
{
	HANDLE		hProcess;
	HANDLE		hThread;
	DWORD   	result = 0;
	DWORD_PTR	addr = 0;

	hProcess = OpenProcess(INJECT_PERMISSIONS, FALSE, pid);

	if(hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Failed to OpenProcess [%x]\n", GetLastError());
		return 0;
	}

	// get the module base
	if((addr = ModuleBase(pid, szPath)) == 0)
	{
		printf("Error locating module %ls\n", szPath);
		return 0;
	}

	printf("Freeing: [%x] %ls\n", addr, szPath);

	hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, (LPVOID)addr, 0, 0);

	if(hThread == INVALID_HANDLE_VALUE)
	{
		printf("Failed to FreeLibrary [%x]\n", GetLastError());
		return 0;
	}

	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &result);
	printf("FreeLibrary: 0x%x\n", result);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 1;
}

//
//	List DLLs in target process
//
int list(DWORD pid)
{
	ModuleBase(pid, 0);
	return 1;
}

//
//	Return the RVA (Virtual Address relative to start of image) of the function in specified DLL
//
DWORD_PTR functionRVA(TCHAR *path, char *func)
{
	HMODULE hModule;
	PVOID   proc;

	if((hModule = LoadLibrary(path)) == 0)
	{
		printf("Failed to LoadLibrary(%ls) [%x]\n", path, GetLastError());
		return 0;
	}

	if((proc = GetProcAddress(hModule, func)) == 0)
	{
		printf("Failed to GetProcAddress(%s) [%x]\n", func, GetLastError());
		return 0;
	}

	FreeLibrary(hModule);
	
	return (DWORD_PTR)proc - (DWORD_PTR)hModule;
}

//
//	Call a function in target process
//
int call(int pid, TCHAR *path, char *func, TCHAR *param)
{
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  result = 0;
	DWORD_PTR addr = 0;
	DWORD_PTR base = 0;
	PVOID  remote;
	size_t len;

	printf("Calling: %ls\n", func);

	hProcess = OpenProcess(INJECT_PERMISSIONS, FALSE, pid);

	if(hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Failed to OpenProcess [%x]\n", GetLastError());
		return 0;
	}

	// get the module base
	if((base = ModuleBase(pid, path)) == 0)
	{
		printf("Error locating module %ls\n", path);
		return 0;
	}

	// copy parameter into target process
	len = (lstrlen(param)+1) * sizeof(TCHAR);
	if((remote = copy_remote(hProcess, param, len)) == 0)
	{
		return 0;
	}

	// work out where the function is located in target address space
	if((addr = functionRVA(path, func)) == 0)
	{
		return 0;
	}

	addr += base;
	printf("Calling: [%x] %ls\n", addr, path);

	hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)addr, (LPVOID)remote, 0, 0);

	if(hThread == INVALID_HANDLE_VALUE)
	{
		printf("Failed to CreateRemoteThread [%x]\n", GetLastError());
		return 0;
	}

	WaitForSingleObject(hThread, INFINITE);

	GetExitCodeThread(hThread, &result);
	printf("called: 0x%x\n", result);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, remote, len, MEM_RELEASE);
	CloseHandle(hProcess);

	return 1;
}

void usage()
{
	puts("Usage: injdll -load  <pid> <dll>");
	puts("       injdll -free  <pid> <dll>");
	puts("       injdll -call  <pid> <dll> <func> <param>");
}

int _tmain(int argc, TCHAR* argv[])
{
	TCHAR szPath[MAX_PATH];
	const TCHAR *proc;
	const TCHAR *cmd;

	DWORD pid;

	if(argc < 3)
	{
		usage();
		return 1;
	}

	if(!EnableDebugPrivilege())
	{
		printf("Failed debug privilege [%x]\n", GetLastError());
		//return 1;
	}

	// get the absolute path to the DLL, because the target process
	// will have a different working directory to which we are running from
	GetFullPathName(argv[3], MAX_PATH, szPath, 0);

	proc = argv[2];
	if(_tcsncmp(proc, TEXT("0x"), 2) == 0)	pid = _tcstol(proc+2, 0, 16);
	else									pid = _tcstol(proc,   0, 10);

	if(pid == 0)
		pid = Process2Pid(proc);

	cmd = argv[1];

	if(_tcscmp(cmd, TEXT("-load")) == 0)
	{
		load(pid, szPath);
	}
	else if(_tcscmp(cmd, TEXT("-free")) == 0 || _tcscmp(cmd, TEXT("-unload")) == 0)
	{
		unload(pid, szPath);
	}
	else if(_tcscmp(cmd, TEXT("-list")) == 0)
	{
		list(pid);
	}
	else if(_tcscmp(cmd, TEXT("-call")) == 0)
	{
		char func[100];

		if(argc != 6)
		{
			usage();
			return 1;
		}

		sprintf_s(func, 100, "%ls", argv[4]);
		call(pid, szPath, func, argv[5]);
	}
	else
	{
		printf("Error: %ls\n", cmd);
	}

	return 0;
}
