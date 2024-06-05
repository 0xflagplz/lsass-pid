// source - https://www.mdsec.co.uk/2022/08/fourteen-ways-to-read-the-pid-for-the-local-security-authority-subsystem-service-lsass/

#include <windows.h>
#include <winsvc.h>  
#include "beacon.h"
#define WINBOOL int

// Link API calls for the BOF linker 
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
WINADVAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);

// Query the 'samss' service for the LSA process ID
DWORD GetLsaPidFromService(void) {
    SC_HANDLE              ManagerHandle = NULL, ServiceHandle = NULL;
    SERVICE_STATUS_PROCESS ProcessInfo;
    HANDLE                 Handle = NULL;
    DWORD                  Length, ProcessId = 0;
    BOOL                   Result;

    do {
        // open the Service Control Manager
        // SC_MANAGER_CONNECT - Service Control Manager (SCM) is a windows predefined constant 
        // From: winsvc.h
        // SC_MANAGER_CONNECT             0x0001  // Connect to the SCM
        // SC_MANAGER_CREATE_SERVICE      0x0002  // Create a service
        // SC_MANAGER_ENUMERATE_SERVICE   0x0004  // Enumerate services
        // SC_MANAGER_LOCK                0x0008  // Lock the SCM
        // SC_MANAGER_QUERY_LOCK_STATUS   0x0010  // Query the lock status
        // SC_MANAGER_MODIFY_BOOT_CONFIG  0x0020  // Modify the boot configuration
        // SC_MANAGER_ALL_ACCESS          0xF003F // Bitwise OR of all permissions
        
        ManagerHandle = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);

        if (!ManagerHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }
        // open the samss service
        // for reference:
        //
        // SC_HANDLE OpenServiceW(
        //   [in] SC_HANDLE hSCManager,
        //   [in] LPCWSTR   lpServiceName,
        //   [in] DWORD     dwDesiredAccess
        // );

        ServiceHandle = ADVAPI32$OpenServiceW(
                            ManagerHandle,
                            L"samss",
                            SERVICE_QUERY_STATUS
                        );

        if (!ServiceHandle) {
            BeaconPrintf(CALLBACK_OUTPUT, "OpenService() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }
        // query the service status to get process information and save to memory location of ProcessInfo
        // for reference:
        //
        // BOOL QueryServiceStatusEx(
        //   [in]            SC_HANDLE      hService,
        //   [in]            SC_STATUS_TYPE InfoLevel,
        //   [out, optional] LPBYTE         lpBuffer,  [buffer location to store into (our var ProcessInfo)]
        //   [in]            DWORD          cbBufSize,
        //   [out]           LPDWORD        pcbBytesNeeded
        // );


        Result = ADVAPI32$QueryServiceStatusEx(
                    ServiceHandle,
                    SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ProcessInfo,
                    sizeof(ProcessInfo),
                    &Length
                );

        if (!Result) {
            BeaconPrintf(CALLBACK_OUTPUT, "QueryServiceStatusEx() failed : %ld\n", KERNEL32$GetLastError());
            break;
        }
        // since we directed the api QueryServiceStatusEx to use the location &ProcessInfo 
        // we can querythe specific parameter of dwProcessId for the processID
        // ProcessID is type SERVICE_STATUS_PROCESS 
        //
        // SERVICE_STATUS_PROCESS Structure:
        //
        //
        // typedef struct _SERVICE_STATUS_PROCESS {
        //   DWORD dwServiceType;
        //   DWORD dwCurrentState;
        //   DWORD dwControlsAccepted;
        //   DWORD dwWin32ExitCode;
        //   DWORD dwServiceSpecificExitCode;
        //   DWORD dwCheckPoint;
        //   DWORD dwWaitHint;
        //   DWORD dwProcessId; (what we want)
        //   DWORD dwServiceFlags;
        // } SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
        ProcessId = ProcessInfo.dwProcessId;
    } while(FALSE);


    // Close the service handle
    if (ServiceHandle) {
        ADVAPI32$CloseServiceHandle(ServiceHandle);
    }
    // Close the SC Manager handle
    if (ManagerHandle) {
        ADVAPI32$CloseServiceHandle(ManagerHandle);
    }


    // BeaconPrintf is defined within beacon.h (several CALLBACK_X options for thee console to interpret the output)

    BeaconPrintf(CALLBACK_OUTPUT, "PID: %lu\n", ProcessId);
    
    return ProcessId;

}

// BOF entry function
int go() {
    GetLsaPidFromService();
    return;
}
