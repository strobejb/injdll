injdll - DLL Injection
----------------------

injdll is a DLL injection tool that was written many years ago. Probably better alternatives out there now. The advantage of this one is that it allows you to unload previously injected DLLs, and also call functions in the target process from the commandline


Listing Modules
---------------

    injdll -list <process>

* process - process ID or name of process

Example:
    injdll -list notepad.exe

Injecting DLLs
---------------

    injdll -load <process> <dll> 

* process - process ID or name of process
* dll - path to DLL to inject

Example:
    injdll -load notepad.exe mydll.dll


Calling functions
-----------------

    injdll -call <process> <dll> <function> <argument>

* process - process ID or name or process
* dll - name or path of DLL in target process
* function - name of exported function in the DLL
* parameter - string argument to pass to the function

The target function must have the following prototype:

    int WINAPI Function ( wchar_t * parameter );


