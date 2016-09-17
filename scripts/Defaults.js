// Description:
// This file is not a modification, but a script that is prepended to every script
// before it is ran by kanan, making everything within this file available to all
// scripts.


// Sends a msg back to kanan's window with the name of the script prepended.
function msg(str) {
    if (scriptName != undefined) {
        send(scriptName + ": " + str);
    }
    else {
        send(str);
    }
}

// Same as above but only outputs a msg when in debug mode.
function dmsg(str) {
    if (debug) {
        msg(str);
    }
}

// Fixes the signature so single ?'s are converted to ??'s.
function fixSig(sig) {
    var oldLen = sig.length;
    var newLen = 0;

    while ((newLen = (sig = sig.replace(' ? ', ' ?? ')).length) != oldLen) {
        oldLen = sig.length;
    }

    return sig;
}

// Scans for patterns in specific modules code section.
function scan(name, sig) {
    if (sig == undefined) {
        sig = name;
        name = 'client.exe';
    }

    sig = fixSig(sig);

    var ranges = Module.enumerateRangesSync(name, 'r-x');
    var address = NULL;

    for (var i = 0; i < ranges.length; ++i) {
        var range = ranges[i];
        var results = Memory.scanSync(range.base, range.size, sig);

        if (results.length > 0) {
            if (results.length > 1) {
                dmsg("More than 1 result for: " + sig);
            }

            address = results[0].address;
            break;
        }
    }

    dmsg(address);

    if (address.isNull()) {
        dmsg("No results for: " + sig);
    }
    else if (debug) {
        // Send the results of the scan back to kanan.py
        send({script: scriptName, signature: sig, address: address});
    }

    return address;
}

// Just adds an offset to the base address of a module.
function moduleOffset(moduleName, offset) {
    var baseAddress = Module.findBaseAddress(moduleName);

    if (baseAddress.isNull()) {
        return NULL;
    }

    return baseAddress.add(offset);
}


// Writes a string to allocated memory.  Make sure theres enough room at the
// address for str.length + 1 (for the trailing zero).
function writeStr(address, str) {
    for (var i = 0; i < str.length; ++i) {
        Memory.writeU8(address.add(i), str.charCodeAt(i));
    }

    Memory.writeU8(address.add(str.length), 0);
}

// Writes a wide str (utf16) to allocated memory.  Make sure theres at least
// str.length * 2 + 2 (for the trailing zero).
function writeWideStr(address, str) {
    for (var i = 0; i < str.length; ++i) {
        Memory.writeU16(address.add(i * 2), str.charCodeAt(i));
    }

    Memory.writeU16(address.add(str.length * 2), 0);
}


// NativeFunctions used by the following functions.
var LoadLibraryA = new NativeFunction(Module.findExportByName('Kernel32.dll', 'LoadLibraryA'),
    'pointer', ['pointer'], 'stdcall');
var GetProcAddress = new NativeFunction(Module.findExportByName('Kernel32.dll', 'GetProcAddress'),
    'pointer', ['pointer', 'pointer'], 'stdcall');
var VirtualAlloc = new NativeFunction(Module.findExportByName('Kernel32.dll', 'VirtualAlloc'),
    'pointer', ['pointer', 'ulong', 'uint32', 'uint32'], 'stdcall');
var VirtualFree = new NativeFunction(Module.findExportByName('Kernel32.dll', 'VirtualFree'),
    'int', ['pointer', 'ulong', 'uint32'], 'stdcall');
var VirtualProtect = new NativeFunction(Module.findExportByName('Kernel32.dll', 'VirtualProtect'),
    'int', ['pointer', 'ulong', 'uint32', 'pointer'], 'stdcall');

// Constants used by the following functions.
var MEM_COMMIT = 0x00001000;
var MEM_RESERVE = 0x00002000;
var MEM_DECOMMIT = 0x4000;
var PAGE_EXECUTE_READWRITE = 0x40;

// Allocates some memory.
function allocateMemory(len) {
    return VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// Frees memory allocated with allocateMemory.
function freeMemory(address, len) {
    return VirtualFree(address, len, MEM_DECOMMIT);
}

// Protects an area of memory and returns the old protection (0 on failure).
function protect(address, len, protect) {
    var oldProtectPtr = allocateMemory(4);
    var result = VirtualProtect(address, len, protect, oldProtectPtr);
    var oldProtect = Memory.readU32(oldProtectPtr);

    freeMemory(oldProtectPtr, 4);

    if (result == 0) {
        msg("Failed to protect " + address);
        return 0; 
    }

    return oldProtect;
}

// Unprotects (sets read, write and executable) an area of memory and returns 
// the old protection (0 on failure).
function unprotect(address, len) {
    return protect(address, len, PAGE_EXECUTE_READWRITE);
}

// Helper that just allocates memory for a str and writes the str to that
// mem.
function allocateStr(str) {
    var mem = allocateMemory(str.length + 1);

    writeStr(mem, str);

    return mem;
}

// Like above but for wide (utf 16) strings.
function allocateWideStr(str) {
    var mem = allocateMemory(str.length * 2 + 2);

    writeWideStr(mem, str);

    return mem;
}

// Frees an allocated str from allocateStr.
function freeStr(str) {
    // We can pass 0 to freeMemory because str must have been allocated with
    // allocateStr (see docs on VirtualFree where the address is the address
    // returned from VirtualAlloc).
    freeMemory(str, 0);
}

// Alias for above.
function freeWideStr(str) {
    freeStr(str);
}

// Loads the dll located at filepath.  Returns the base address of the loaded
// dll or NULL.
function loadDll(filepath) {
    var str = allocateStr(filepath);
    var result = LoadLibraryA(str);

    freeStr(str);

    return result;
}

// Gets the address of an exported function.
function getProcAddress(moduleName, funcName) {
    // Search the currently loaded modules for the function.
    var addr = Module.findExportByName(moduleName, funcName);

    if (!addr.isNull()) {
        return addr;
    }

    // Otherwise, fallback to the win32 api way of doing things. If the module
    // isn't already loaded it will be.
    var str = allocateStr(funcName);
    var result = GetProcAddress(loadDll(moduleName), str);

    freeStr(str);

    return result;
}

// Wrapper for NativeFunction that uses the above getProcAddress.
function native(moduleName, funcName, returnType, paramTypes, callType) {
    return new NativeFunction(getProcAddress(moduleName, funcName), returnType, paramTypes, callType);
}

// Validates a patch address.
// TODO: Make this more robust.
function isValidPatchAddress(addr) {
    return (!addr.isNull() && addr.toInt32() > 1000);
}

// Patches an array of bytes or a single byte.
function patch(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch.");
        return;
    }

    if (testing) {
        return;
    }

    if (!Array.isArray(c)) {
        c = [c];
    }

    var p = unprotect(addr, c.length);

    for (var i = 0; i < c.length; ++i) {
        if (c[i] >= 0 && c[i] <= 0xFF) {
            Memory.writeU8(addr.add(i), c[i]);
        }
    }

    protect(addr, c.length, p);
}

// Patches a byte (8 bits). This is the same as calling the above patch() 
// function with a single byte as the argument.
function patchByte(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch byte.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 1);

    Memory.writeU8(addr, c);
    protect(addr, 1, p);
}

// Patches a word (16 bits, shorts).
function patchWord(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch word.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 2);

    Memory.writeU16(addr, c);
    protect(addr, 2, p);
}

// Patches a dword (32 bits, ints, longs, addresses).
function patchDword(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch dword.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 4);

    Memory.writeU32(addr, c);
    protect(addr, 4, p);
}

// Patches a qword (64 bits, long longs, 64-bit addresses).
function patchQword(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch qword.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 8);

    Memory.writeU64(addr, c);
    protect(addr, 8, p);
}

// Patches a float (32 bits, no doubles).
function patchFloat(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch float.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 4);

    Memory.writeFloat(addr, c);
    protect(addr, 4, p);
}

// Patches a double (64 bits).
function patchDouble(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch double.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 8);

    Memory.writeDouble(addr, c);
    protect(addr, 8, p);
}

// Patches a pointer.
function patchPointer(addr, c) {
    if (!isValidPatchAddress(addr)) {
        msg("Failed to patch pointer.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(addr, 4);

    Memory.writePointer(addr, c);
    protect(addr, 4, p);
}

// Same as above but called address instead.
var patchAddress = patchPointer;

// Aliases for the above functions.
var writeByte = patchByte;
var writeWord = patchWord;
var writeDword = patchDword;
var writeQword = patchQword;
var writeFloat = patchFloat;
var writeDouble = patchDouble;
var writePointer = patchPointer;
var writeAddress = patchAddress;

// Copies bytes.
function copy(dst, src, len) {
    if (!isValidPatchAddress(dst) || !isValidPatchAddress(src)) {
        msg("Failed to copy.");
        return;
    }

    if (testing) {
        return;
    }

    var dstp = unprotect(dst, len);
    var srcp = unprotect(src, len);

    Memory.copy(dst, src, len);

    protect(src, len, srcp);
    protect(dst, len, dstp);
}

// Inserts a 5-byte jmp at the address to the destination. 
// NOTE: Make sure there is room for the jmp!!!!
function insertJmp(address, destination) {
    if (!isValidPatchAddress(address)) {
        msg("Failed to insert jmp.");
        return;
    }

    if (testing) {
        return;
    }

    var p = unprotect(address, 5);

    Memory.writeU8(address, 0xE9);
    Memory.writeS32(address.add(1), destination.toInt32() - address.toInt32() - 5);

    protect(address, 5, p);
}
