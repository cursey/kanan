// Originally found in Fantasia.

// Description:
// Load files in the /data/ folder of kanan before reading .pack files, then redirect them to Mabinogi without touching Mabinogi's directory.
// This script is most effective when kanan is ran **BEFORE** mabi starts.
// When running this script in debug mode, expect a crazy amount of
// output.  Because of the crazy amount of debug text, most of it is only
// outputed when also ran in verbose mode (-d -v).

// SetLookUpOrder is only called once shortly after mabi starts, so we call it
// again telling it to load from the data folder.
var SetLookUpOrderPtr = scan('55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC 0C 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 ?? ?? ?? ?? 8B F1 89 75 EC E8 ?? ?? ?? ?? 84 C0');
var SetLookUpOrder = new NativeFunction(SetLookUpOrderPtr, 'int', ['pointer', 'int'], 'thiscall');
var CFileSystem = Memory.readPointer(scan('B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 7B 13 00').add(1));

SetLookUpOrder(CFileSystem, 0); // The 0 means data folder first!

dmsg("Called CFileSystem::SetLookUpOrder");

// Allocate space for the redirected filenames.
var filenameMem = allocateMemory(4096);

// We intercept the following functions because mabi uses them for file loading
// and discovery.

//
// NtCreateFile
//
Interceptor.attach(getProcAddress('ntdll.dll', 'NtCreateFile'), {
    onEnter(args) {
        var ObjectAttributesPtr = args[2];
        var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
        var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
        var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);

        // We only redirect filenames that have \data\ in them.
        if (ObjectName.includes('\\data\\')) {
            var newFilename = "\\??\\" + path + ObjectName.substr(ObjectName.indexOf('\\data\\'));

            // Write the string.
            Memory.writeUtf16String(filenameMem, newFilename);

            // Change the UNICODE_STRING.
            Memory.writeU16(ObjectNamePtr, newFilename.length * 2); // Length
            Memory.writeU16(ObjectNamePtr.add(2), 4096); // MaximumLength
            Memory.writePointer(ObjectNamePtr.add(4), filenameMem);
        }

        if (debug && verbose) {
            var ObjectAttributesPtr = args[2];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);

            msg("NtCreateFile: " + ObjectName);
        }
    }
});

//
// NtOpenFile
//
Interceptor.attach(getProcAddress('ntdll.dll', 'NtOpenFile'), {
    onEnter(args) {
        var ObjectAttributesPtr = args[2];
        var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
        var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
        var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);

        // We only redirect filenames that have \data\ in them.
        if (ObjectName.includes('\\data\\')) {
            var newFilename = "\\??\\" + path + ObjectName.substr(ObjectName.indexOf('\\data\\'));

            // Write the string.
            Memory.writeUtf16String(filenameMem, newFilename);

            // Change the UNICODE_STRING.
            Memory.writeU16(ObjectNamePtr, newFilename.length * 2); // Length
            Memory.writeU16(ObjectNamePtr.add(2), 4096); // MaximumLength
            Memory.writePointer(ObjectNamePtr.add(4), filenameMem);
        }

        if (debug && verbose) {
            var ObjectAttributesPtr = args[2];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);

            msg("NtOpenFile: " + ObjectName);
        }
    }
});

