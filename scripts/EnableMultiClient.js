// Originally found in JinsuNogi.

// Description:
// Remove the limitation of one client.exe instance, allowing you to launch multiple clients. 
// Take note you'll need a method to bypass the launcher as well, for more information refer to https://github.com/cursey/kanan/wiki/List-of-modifications#enablemulticlientjs-created-by-cursey

// Walkthrough:
// Intuition: win32 apps use CreateMutex* to limit the number of instances
// (see https://support.microsoft.com/en-us/kb/243953).  Turns out mabi does
// this as well.  So all we need to do is close the handle to the mutex mabi
// creates and we should be able to open another instance of mabi.
//
// IDA unicode string view -> code.client.msg.error.14
// xrefs (there should only be 1 or 2 but within the same function).
// xrefs to this function (there should only be 1).
// after analysing this function you can see its checking the return value of
// one function, so view that one.
// after analysing this function you should see that it moves a static address
// into ecx, calls a function then compares the value before eventually
// returning.  If you peer inside this function you should see calls to
// CreateMutexW, GetLastError, and WaitForSingleObject.  If so, the static
// address that was moved into ecx before the call is the mutex handle.
// If you xrefs on that static address you should see it used in two places,
// this function where its created using CreateMutexW and a location where its
// closed using SetHandleInformation and CloseHandle, we just repeat that
// process here.

// The native functions we use.
var SetHandleInformation = native('kernel32.dll', 'SetHandleInformation', 'int', ['pointer', 'uint32', 'uint32'], 'stdcall');
var CloseHandle = native('kernel32.dll', 'CloseHandle', 'int', ['pointer'], 'stdcall');
var GetLastError = native('kernel32.dll', 'GetLastError', 'uint32', [], 'stdcall');

// Find the mutex handle.
var movHandle = scan('B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 52 A1');
var mutexHandlePtr = Memory.readPointer(movHandle.add(1));
var mutexHandle = 0;

while (mutexHandle == 0) {
    mutexHandle = Memory.readPointer(mutexHandlePtr);
    Thread.sleep(1);
}

// Close it.
if (SetHandleInformation(mutexHandle, 2, 0) == 0) {
    msg("SetHandleInformation failure: " + GetLastError());
}

if (CloseHandle(mutexHandle) == 0) {
    msg("Mutex close failure: " + GetLastError());
}
else {
    dmsg("Mutex close success!");
}
