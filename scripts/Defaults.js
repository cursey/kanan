// Helper to scan for patterns in specific modules code section.
function scan(name, sig) {
    var ranges = Module.enumerateRangesSync(name, 'r-x');

    for (var i = 0; i < ranges.length; ++i) {
        var range = ranges[i];
        var results = Memory.scanSync(range.base, range.size, sig);

        if (results.length > 0) {
            return results[0].address;
        }
    }

    return NULL;
}

function patch(addr, c) {
    Memory.protect(addr, 4096, 'rwx');
    Memory.writeU8(addr, c);
    Memory.protect(addr, 4096, 'r-x');
}
