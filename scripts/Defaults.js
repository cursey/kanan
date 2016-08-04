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

// Scans for patterns in specific modules code section.
function scan(name, sig) {
    if (sig == undefined) {
        sig = name;
        name = 'client.exe';
    }

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
        msg("No results for: " + sig);
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

// Patches an array of bytes.
function patch(addr, c) {
    if (addr.isNull()) {
        msg("Failed to patch.");
        return;
    }

    if (testing) {
        return;
    }

    if (!Array.isArray(c)) {
        c = [c];
    }

    Memory.protect(addr, c.length, 'rwx');

    for (var i = 0; i < c.length; ++i) {
        if (c[i] >= 0 && c[i] <= 0xFF) {
            Memory.writeU8(addr.add(i), c[i]);
        }
    }

    Memory.protect(addr, c.length, 'r-x');
}

// Copies bytes.
function copy(dst, src, len) {
    if (dst.isNull() || src.isNull()) {
        msg("Failed to copy.");
        return;
    }

    if (testing) {
        return;
    }

    Memory.protect(dst, len, 'rwx');
    Memory.protect(src, len, 'rwx');

    Memory.copy(dst, src, len);

    Memory.protect(src, len, 'r-x');
    Memory.protect(dst, len, 'r-x');
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

// Gets the address of an exported function.
function getProcAddress(moduleName, funcName) {
    return Module.findExportByName(moduleName, funcName);
}

// Allocates some memory.
var VirtualAlloc = new NativeFunction(getProcAddress('Kernel32.dll', 'VirtualAlloc'),
        'pointer', ['pointer', 'ulong', 'uint32', 'uint32'], 'stdcall');

function allocateMemory(len) {
    // 0x3000 = MEM_COMMIT | MEM_RESERVE
    // 0x40 = PAGE_EXECUTE_READWRITE
    return VirtualAlloc(NULL, len, 0x3000, 0x40);
}

// Frees memory allocated with allocateMemory.
var VirtualFree = new NativeFunction(getProcAddress('Kernel32.dll', 'VirtualFree'),
        'int', ['pointer', 'ulong', 'uint32'], 'stdcall');

function freeMemory(address, len) {
    // 0x4000 = MEM_DECOMMIT
    return VirtualFree(address, len, 0x4000);
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
var LoadLibraryA = new NativeFunction(getProcAddress('Kernel32.dll', 'LoadLibraryA'),
        'pointer', ['pointer'], 'stdcall');

function loadDll(filepath) {
    var str = allocateStr(filepath);
    var result = LoadLibraryA(str);

    freeStr(str);

    return result;
}

