// This script tells mabi to load from its /data/ folder before looking through
// its loaded .pack files.  It also redirects mabi's /data/ folder to be
// kanan's /data/ folder so that you may mod files without touching mabi's
// directory.
//
// This script is most effective when kanan is ran **BEFORE** mabi starts.
//
// NOTE: When running this script in debug mode, expect a crazy amount of
// output.  Disable this script when debugging something else.

// SetLookUpOrder is only called once shortly after mabi starts, so we call it
// again telling it to load from the data folder.
var SetLookUpOrderPtr = scan('55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC 0C 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 ?? ?? ?? ?? 8B F1 89 75 EC E8 ?? ?? ?? ?? 84 C0');
var SetLookUpOrder = new NativeFunction(SetLookUpOrderPtr, 'int', ['pointer', 'int'], 'thiscall');
var CFileSystem = Memory.readPointer(scan('B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 7B 13 00').add(1));

SetLookUpOrder(CFileSystem, 0); // The 0 means data folder first!

dmsg("Called CFileSystem::SetLookUpOrder");

// Allocate space for the redirected filenames.
var filenameMem = allocateMemory(4096);

// Helper to automatically redirect filenames.
function getNewFilename(filenamePtr) {
    var filename = Memory.readUtf16String(filenamePtr);

    // We only redirect filenames that have \data\ in them.
    if (filename.includes('\\data\\')) {
        var newFilename = path + filename.substr(filename.indexOf('\\data\\'));

        Memory.writeUtf16String(filenameMem, newFilename);

        return filenameMem;
    }

    return filenamePtr;
}

// We intercept the following functions because mabi uses them for file loading
// and discovery.  We use the above helper to redirect files.

//
// GetFileAttributes
//
Interceptor.attach(getProcAddress('kernel32.dll', 'GetFileAttributesW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("GetFileAttributesW: " + Memory.readUtf16String(args[0]));
    }
});

//
// GetFileAttributesEx
//
Interceptor.attach(getProcAddress('kernel32.dll', 'GetFileAttributesExW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("GetFileAttributesExW: " + Memory.readUtf16String(args[0]));
    }
});

//
// GetFullPathName
//
Interceptor.attach(getProcAddress('kernel32.dll', 'GetFullPathNameW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("GetFullPathNameW: " + Memory.readUtf16String(args[0]));
    }
});

//
// CreateFile
//
Interceptor.attach(getProcAddress('kernel32.dll', 'CreateFileW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("CreateFileW: " + Memory.readUtf16String(args[0]));
    }
});

//
// FindFirstFile
//
Interceptor.attach(getProcAddress('kernel32.dll', 'FindFirstFileW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("FindFirstFileW: " + Memory.readUtf16String(args[0]));
    }
});

//
// FindFirstFileEx
//
Interceptor.attach(getProcAddress('kernel32.dll', 'FindFirstFileExW'), {
    onEnter(args) {
        args[0] = getNewFilename(args[0]);

        dmsg("FindFirstFileExW: " + Memory.readUtf16String(args[0]));
    }
});

// The following don't modify their arguments because mabi does not directly
// use the Nt* functions.  These are only intercepted for debugging.
if (debug) {
    //
    // NtCreateFile
    //
    var NtCreateFile = {
        onEnter(args) {
            var ObjectAttributesPtr = args[2];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
            var filename = ObjectName;

            msg("NtCreateFile: " + filename);
        }
    };

    Interceptor.attach(getProcAddress('ntdll.dll', 'NtCreateFile'), NtCreateFile);

    //
    // NtOpenFile
    //
    Interceptor.attach(getProcAddress('ntdll.dll', 'NtOpenFile'), {
        onEnter(args) {
            var ObjectAttributesPtr = args[2];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
            var filename = ObjectName;

            msg("NtOpenFile: " + filename);
        }
    });

    //
    // NtQueryDirectoryFile
    //
    Interceptor.attach(getProcAddress('ntdll.dll', 'NtQueryDirectoryFile'), {
        onEnter(args) {
            var FileNamePtr = args[9];

            if (FileNamePtr.isNull()) {
                return;
            }

            var FileNameBufferPtr = Memory.readPointer(FileNamePtr.add(4));
            var filename = Memory.readUtf16String(FileNameBufferPtr);

            msg("NtQueryDirectoryFile: " + filename);
        }
    });

    //
    // NtQueryFullAttributesFile
    //
    Interceptor.attach(getProcAddress('ntdll.dll', 'NtQueryFullAttributesFile'), {
        onEnter(args) {
            var ObjectAttributesPtr = args[0];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
            var filename = ObjectName;

            msg("NtQueryFullAttributesFile: " + filename);
        }
    });

    //
    // NtQueryAttributesFile
    //
    Interceptor.attach(getProcAddress('ntdll.dll', 'NtQueryAttributesFile'), {
        onEnter(args) {
            var ObjectAttributesPtr = args[0];
            var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
            var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
            var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
            var filename = ObjectName;

            msg("NtQueryAttributesFile: " + filename);
        }
    });
}
