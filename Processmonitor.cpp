#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")

#ifndef SystemHandleInformation
#define SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)16)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// the code find all handle in system 
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);


typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG         HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

// Enable Privilege Debug  run as administretor 

bool () {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{ 1, {{luid, SE_PRIVILEGE_ENABLED}} };
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp,
        sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// find process lsass 

DWORD GetLsassPid() {
    PROCESSENTRY32 pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    while (Process32Next(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

std::wstring GetProcessName(DWORD pid) {
    PROCESSENTRY32 pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"";

    std::wstring name;
    while (Process32Next(snap, &pe)) {
        if (pe.th32ProcessID == pid) {
            name = pe.szExeFile;
            break;
        }
    }
    CloseHandle(snap);
    return name;
}

int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Could not enable SeDebugPrivilege\n";
        return 1;
    }
    std::cout << "[+] SeDebugPrivilege enabled\n";

 
    std::wcout << L"[+] LSASS PID: " << lsassPid << L"\n";

    std::wofstream logFile("log.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "[-] Could not open log.txt for writing.\n";
        return 1;
    }

    while (true) {
        std::vector<BYTE> buffer;
        ULONG bufferSize = 0;
        NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(
                SystemHandleInformation,
                buffer.data(),
                bufferSize,
                &bufferSize
            );
            if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
                std::cerr << "[-] NtQuerySystemInformation failed: 0x"
                    << std::hex << status << std::dec << "\n";
                return 1;
            }
        }

        auto pInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer.data());

        for (ULONG i = 0; i < pInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& h = pInfo->Handles[i];

            // Skip handles from SYSTEM (pid 4), idle, etc. (optional)
            if (h.ProcessId < 10) continue;

            // Skip lsass.exe holding itself
            if (h.ProcessId == lsassPid) continue;

            HANDLE hSrc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.ProcessId);
            if (!hSrc) continue;

            HANDLE hDup = nullptr;
            if (DuplicateHandle(
                hSrc,
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(h.Handle)),
                GetCurrentProcess(),
                &hDup,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS
            )) {
                DWORD targetPid = GetProcessId(hDup);
                if (targetPid == lsassPid) {
                    auto procName = GetProcessName(h.ProcessId);

                    std::wcout << L"PID " << h.ProcessId
                        << L" (" << procName << L") -> Handle: 0x"
                        << std::hex << h.Handle << std::dec << L"\n";

                    logFile << L"PID " << h.ProcessId
                        << L" (" << procName << L") -> Handle: 0x"
                        << std::hex << h.Handle << std::dec << L"\n";
                }
                CloseHandle(hDup);
            }
            CloseHandle(hSrc);
        }

        logFile.flush();
        Sleep(1000);
        // 1 second 
    }

    logFile.close();
    return 0;
}
