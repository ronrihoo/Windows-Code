// ServTrig
//
// Brief:  turns a Windows service on/off based off of what negates its state at
//         the time of switching its state.
//
// Purpose:  to show that any program could include a little bit of code to turn
//           a service on/off. Social Engineering methods could be carried out
//           to elicit an individual to install a legitimate program that depends
//           on a specific service which the attacker knows how to exploit well.
//
// Usage: run at command line with administrative privileges. Please do not run
//        without the command line argument, as it will not function correctly,
//        and not enough error checking has been implemented.
//
// Example: ServTrig "AudioSrv"
//
// Author: Ronald Rihoo
// 
#include <iostream>
#include <iomanip>
#include <windows.h>
#include <string>
#include "stdafx.h"

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
    // Long Pointer to Constant Wide String
    // The string is stored in 2 bytes (wide) and deals with non-ASCII strings
    // To assign a normal C literal string, it must be prefixed with an L, like:
    // LPCWSTR service_name = L"serviceName";
    LPCWSTR service_name;                   // service name will be held in this variable

    service_name = argv[1];

    // we could just use argv[1] in the argument of OpenService, but I left this open
    // for anyone who wants to just change a service state without prompting the user,
    // 'cause discovering LPCWSTR might be a pain


    // Jargon
    //              "SC"    :       service control
    //
    // SC_HANDLE and OpenSCManager, from winsvc.h, Copyright (c) Microsoft Corporation
    // ...      ...
    // 660      DECLARE_HANDLE(SC_HANDLE);
    // 661      typedef SC_HANDLE   *LPSC_HANDLE;
    // ...      ...
    // 1302     OpenSCManagerW(
    // 1303     _In_opt_        LPCWSTR                lpMachineName,
    // 1304     _In_opt_        LPCWSTR                lpDatabaseName,
    // 1305     _In_            DWORD                  dwDesiredAccess
    // 1306     );
    // 1307     #ifdef UNICODE
    // 1308     #define OpenSCManager  OpenSCManagerW
    // ...      ...
    //
    // specifiy which computer, and which one of its service databases we want to gain access to, and how much access we want
    SC_HANDLE database_handle = OpenSCManager(  NULL,                       // name of computer. If NULL, then points to the local computer
                                                SERVICES_ACTIVE_DATABASE,   // name of database. This should be "SERVICES_ACTIVE_DATABASE"
                                                SC_MANAGER_ALL_ACCESS       // what sort of access? All Access rights in the table
                                                );

    // now use our database_handle to control a service, but which service? The one that's passed as a parameter when running this program.
    SC_HANDLE control_handle = OpenService( database_handle,            // handle to the service control manager
                                            service_name,               // name of the service to be opened. We're taking the first parameter given to main
                                            SC_MANAGER_ALL_ACCESS       // what sort of access? All Access rights in the table
                                            );
 

    SERVICE_STATUS_PROCESS status;          // status is now our own arbitrarily named copy of the SERVICE_STATUS_PROCESS from winsvc.h
                                            // this means that we now have dwCurrentState under status to check for a process' current state
                                            // 
                                            // check out line 695 in winsvc.h for the SERVICE_STATUS_PROCESS definition
    DWORD buffer_size;          // DWORD is an unsigned long int (no negative numbers)
    QueryServiceStatusEx(control_handle, SC_STATUS_PROCESS_INFO,(LPBYTE) &status,sizeof(SERVICE_STATUS_PROCESS), &buffer_size);
 
    // From line 114 to 123 of the winsvc.h, we have hex definitions for names that have been arbitrarily given to
    // remind us of their correlation to the "Service State." We will use SERVICE_RUNNING, which is just a label for the
    // hex number 0x00000004, as shown below,
    //
    // line 114-123, winsvc.h
    // ...     ...                                    ...
    // // 
    // // Service State -- for CurrentState
    // //
    // #define SERVICE_STOPPED                        0x00000001
    // #define SERVICE_START_PENDING                  0x00000002
    // #define SERVICE_STOP_PENDING                   0x00000003
    // #define SERVICE_RUNNING                        0x00000004
    // #define SERVICE_CONTINUE_PENDING               0x00000005
    // #define SERVICE_PAUSE_PENDING                  0x00000006
    // #define SERVICE_PAUSED                         0x00000007
    // ...     ...                                    ...

    cout << "Current State: " <<  showbase << internal << setfill('0') << hex << setw(10) << status.dwCurrentState << endl;

    if (status.dwCurrentState == SERVICE_RUNNING)
    {        
        cout << "Attempting to stop service... ";

        if (ControlService(control_handle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &status))
        {
            // this is a lie, since it's probably going to pend on most machines at this instance
            cout << "Successfully stopped!" << endl; 
        }
        else
            cout << "Failed to stop." << endl;
    }
    else
    {     
        cout << "Attempting to start service... ";

        if (StartService(control_handle, NULL, NULL))
        {
            // this is a lie too, since this, too, will probably pend on most machines at this time
            cout << "Successfully started!" << endl;
        }
        else
            cout << "Failed to start." << endl;
    }
 
    CloseServiceHandle(control_handle);
    CloseServiceHandle(database_handle); 

    return 0;
}
