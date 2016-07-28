// This script tells mabi to load from its /data/ folder before looking through
// its loaded .pack files.  It also redirects mabi's /data/ folder to be
// kanan's /data/ folder so that you may mod files without touching mabi's
// directory.
//
// This script is most effective when kanan is ran **BEFORE** mabi starts.
//
// NOTE: When running this script in debug mode, expect a crazy amount of
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
var utf16Filename = filenameMem;

// Helpers to automatically redirect filenames.
function getNewUtf16Filename(filenamePtr) {
    var filename = Memory.readUtf16String(filenamePtr);

    // We only redirect filenames that have \data\ in them.
    if (filename.includes('\\data\\')) {
        var newFilename = path + filename.substr(filename.indexOf('\\data\\'));

        Memory.writeUtf16String(utf16Filename, newFilename);

        return utf16Filename;
    }

    return filenamePtr;
}

// We intercept the following functions because mabi uses them for file loading
// and discovery.  We use the above helper to redirect files.

//
// GetFileAttributes
//
var onGetFileAttributesW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("GetFileAttributesW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'GetFileAttributesW'), onGetFileAttributesW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'GetFileAttributesW'), onGetFileAttributesW);

//
// GetFileAttributesEx
//
var onGetFileAttributesExW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("GetFileAttributesExW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'GetFileAttributesExW'), onGetFileAttributesExW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'GetFileAttributesExW'), onGetFileAttributesExW);

//
// GetFullPathName
//
var onGetFullPathNameW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("GetFullPathNameW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'GetFullPathNameW'), onGetFullPathNameW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'GetFullPathNameW'), onGetFullPathNameW);

//
// CreateFile
//
var onCreateFileW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("CreateFileW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'CreateFileW'), onCreateFileW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'CreateFileW'), onCreateFileW);

//
// FindFirstFile
//
var onFindFirstFileW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("FindFirstFileW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'FindFirstFileW'), onFindFirstFileW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'FindFirstFileW'), onFindFirstFileW);

//
// FindFirstFileEx
//
var onFindFirstFileExW = {
    onEnter(args) {
        args[0] = getNewUtf16Filename(args[0]);

        if (verbose) {
            dmsg("FindFirstFileExW: " + Memory.readUtf16String(args[0]));
        }
    }
};

Interceptor.attach(getProcAddress('kernel32.dll', 'FindFirstFileExW'), onFindFirstFileExW);
Interceptor.attach(getProcAddress('kernelbase.dll', 'FindFirstFileExW'), onFindFirstFileExW);

// The following don't modify their arguments because mabi does not directly
// use the Nt* functions.  These are only intercepted for debugging.
if (debug && verbose) {
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

            //var filename = Memory.readUtf16String(filenamePtr);

            // We only redirect filenames that have \data\ in them.
            if (filename.includes('\\data\\')) {
                var newFilename = "\\??\\" + path + filename.substr(filename.indexOf('\\data\\'));

                // Write the string.
                Memory.writeUtf16String(utf16Filename.add(1024), newFilename);

                // Change the UNICODE_STRING.
                Memory.writeU16(ObjectNamePtr, newFilename.length * 2); // Length
                Memory.writeU16(ObjectNamePtr.add(2), 1024); // MaximumLength
                Memory.writePointer(ObjectNamePtr.add(4), utf16Filename.add(1024));

                var ObjectAttributesPtr = args[2];
                var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
                var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
                var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
                var filename = ObjectName;

                msg("NtCreateFile: " + filename);
                msg("len: " + Memory.readU16(ObjectNamePtr));
                msg("maxlen: " + Memory.readU16(ObjectNamePtr.add(2)));
            }
            else {
                msg("NtCreateFile: " + filename);
            }
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

            //var filename = Memory.readUtf16String(filenamePtr);

            // We only redirect filenames that have \data\ in them.
            if (filename.includes('\\data\\')) {
                var newFilename = "\\??\\" + path + filename.substr(filename.indexOf('\\data\\'));

                // Write the string.
                Memory.writeUtf16String(utf16Filename.add(1024), newFilename);

                // Change the UNICODE_STRING.
                Memory.writeU16(ObjectNamePtr, newFilename.length * 2); // Length
                Memory.writeU16(ObjectNamePtr.add(2), 1024); // MaximumLength
                Memory.writePointer(ObjectNamePtr.add(4), utf16Filename.add(1024));

                var ObjectAttributesPtr = args[2];
                var ObjectNamePtr = Memory.readPointer(ObjectAttributesPtr.add(8));
                var ObjectNameBufferPtr = Memory.readPointer(ObjectNamePtr.add(4));
                var ObjectName = Memory.readUtf16String(ObjectNameBufferPtr);
                var filename = ObjectName;

                msg("NtOpenFile: " + filename);
                msg("len: " + Memory.readU16(ObjectNamePtr));
                msg("maxlen: " + Memory.readU16(ObjectNamePtr.add(2)));
            }
            else {
                msg("NtOpenFile: " + filename);
            }
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
