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
            address = results[0].address;
            break;
        }
    }

    if (debug)
        send(address);

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

// Patches a byte.
function patch(addr, c) {
    if (!testing) {
        Memory.protect(addr, 4096, 'rwx');
        Memory.writeU8(addr, c);
        Memory.protect(addr, 4096, 'r-x');
    }
}

// Writes a string to allocated memory.  Make sure theres enough room at the 
// address for str.length + 1 (for the trailing zero).
function writeStr(address, str) {
    for (var i = 0; i < str.length; ++i) {
        Memory.writeS8(address.add(i), str.charCodeAt(i)); 
    }

    Memory.writeU8(address.add(str.length), 0);
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

// Loads the dll located at filepath.  Returns the base address of the loaded
// dll or NULL.
var LoadLibraryA = new NativeFunction(getProcAddress('Kernel32.dll', 'LoadLibraryA'),
        'pointer', ['pointer'], 'stdcall');

function loadDll(filepath) {
    var mem = allocateMemory(filepath.length + 1);

    writeStr(mem, filepath);

    var result = LoadLibraryA(mem);

    freeMemory(mem, filepath.length + 1);

    return result;
}

