// Description: 
// Lower your MTU to reduce latency between the client and server.
// Fore more information refer to http://wiki.mabinogiworld.com/view/Lag#Lowering_your_Maximum_Transmission_Unit_.28MTU.29

// Configuration:
// To change MTU on login/channel change:
// 1. Set NET_INTERFACE to the correct interface name for your computer.
// 2. Set LOW_MTU to the lowest value you're comfortable with, 386 is a good default.
var NET_INTERFACE = "Ethernet"; //"Wi-Fi";
var LOW_MTU = 386;
var NORM_MTU = 1500;
/*
      1500 <768 < 512 < 386 < 256 < 128 < 48
  Slow<------------------------------------>Fast

  Win8.x/10
    Wired router:     netsh interface ipv4 set subinterface "Ethernet" mtu=386 store=persistent
    Wireless router:  netsh interface ipv4 set subinterface "Wi-Fi" mtu=386 store=persistent
  Win7/Vista
    Wired router:     netsh interface ipv4 set subinterface "Local Area Connection" mtu=386 store=persistent
    Wireless router:  netsh interface ipv4 set subinterface "Wireless Network Connection" mtu=386 store=persistent
*/

// Native functions used by this script.
var CreateProcessA = native('Kernel32.dll', 'CreateProcessA', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'ulong', 'pointer', 'pointer', 'pointer', 'pointer'], 'stdcall');
var WaitForSingleObject = native('Kernel32.dll', 'WaitForSingleObject', 'ulong', ['pointer', 'uint32'], 'stdcall');
var GetExitCodeProcess = native('Kernel32.dll', 'GetExitCodeProcess', 'int', ['pointer', 'pointer'], 'stdcall');
var CloseHandle = native('Kernel32.dll', 'CloseHandle', 'int', ['pointer'], 'stdcall');

// Constants used by this script.
var FALSE = 0;
var CREATE_NO_WINDOW = 0x08000000;
var NORMAL_PRIORITY_CLASS = 0x00000020;

// Returns -1 on failure, otherwise returns the exitcode of the process it 
// it created.
// 
// NOTE: If the process' exitcode is -1 then who knows if this function was 
// successful or not.
function runProcess(name, params) {
    var paramsPtr = allocateStr(name + ' ' + params);
    var startupInfoPtr = allocateMemory(68);
    var processInfoPtr = allocateMemory(16);

    patchDword(startupInfoPtr, 68); // STARTUPINFO.cb = sizeof(STARTUPINFO) 

    var result = CreateProcessA(NULL, paramsPtr, NULL, NULL, FALSE, CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS, NULL, NULL, startupInfoPtr, processInfoPtr);

    dmsg("CreateProcess for " + name + " " + params + ": " + result);

    if (result != 0) {
         var processHandle = Memory.readPointer(processInfoPtr);
         var threadHandle = Memory.readPointer(processInfoPtr.add(4));
         var exitCodePtr = allocateMemory(4);

         result = WaitForSingleObject(processHandle, 5000);

         dmsg("WaitForSingleObject for " + processHandle + ": " + result);

         result = GetExitCodeProcess(processHandle, exitCodePtr);

         dmsg("GetExitCodeProcess for " + processHandle + ": " + result);

         result = Memory.readU32(exitCodePtr);

         dmsg("Exit code: " + Memory.readU32(exitCodePtr));

         freeMemory(exitCodePtr, 4);
         CloseHandle(threadHandle);
         CloseHandle(processHandle);
    }
    else {
        msg("Failed to start " + name + " with params " + params);
        result = -1;
    }

    freeMemory(processInfoPtr, 16);
    freeMemory(startupInfoPtr, 68);
    freeStr(paramsPtr);

    return result;
}

// This function calls socket() and connect().
var createConnectionPtr = scan('55 8B EC 83 EC 08 56 57 8B 7D 0C 8B CF');

Interceptor.attach(createConnectionPtr, {
    onEnter(args) {
        // Lower MTU
        runProcess('netsh.exe', 'interface ipv4 set subinterface "' + NET_INTERFACE + '" mtu=' + LOW_MTU + ' store=persistent'); 
    },
    onLeave(retval) {
        // Raise MTU back to normal (1500)
        runProcess('netsh.exe', 'interface ipv4 set subinterface "' + NET_INTERFACE + '" mtu=' + NORM_MTU + ' store=persistent'); 
    }
});
