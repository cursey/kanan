// Originally found in Fantasia.

// Description: 
// Display Combat Power (CP) information when holding down ALT in numerical value as opposed to just ranking. (example: weakest White Spider > 50 weakest White Spider)

// Walkthrough: 
// IDA unicode string view -> <mini>WEAKEST </mini> (there are others for
// strong, awful, etc)
// check the xrefs (should only be one)
// These are the strings we replace and this is the function we intercept.

var isPlayerCheck1 = scan('0F 85 ?? ?? ?? ?? 57 8B CE E8 ?? ?? ?? ?? 84 C0 75 76'); // This is from the function that calls the one we found.
var isPlayerCheck2 = scan('0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B 06'); // This is in the function we found near the top.
var isLocalPlayerCheck = scan('0F 85 ?? ?? ?? ?? 89 5D F0 C7 45 ?? ?? ?? ?? ?? 89 5D E8'); // this is in the function we found right before the switch.
var switchptr = scan('FF 24 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? EB 1A 68 ?? ?? ?? ?? EB 13 68 ?? ?? ?? ?? EB 0C 68 ?? ?? ?? ?? EB 05 68 ?? ?? ?? ?? 8D 4D F0 E8 ?? ?? ?? ?? 6A 01'); // This is also in the function we found.

patch(isPlayerCheck1, [0x90, 0xE9]);
patch(isPlayerCheck2, Array(6).fill(0x90));
patch(isLocalPlayerCheck, Array(6).fill(0x90));

// Make room for our replacement strings.  We will write the cp to each one.
var strMem = allocateMemory(1000);

var weakestStr = strMem.add(0);
var weakStr = strMem.add(200);
var strongStr = strMem.add(400);
var awfulStr = strMem.add(600);
var bossStr = strMem.add(800);

var p = unprotect(switchptr, 1000);

// Overwrite the location of the default strings with our new strings.
Memory.writePointer(switchptr.add(7 + 1), weakestStr);
Memory.writePointer(switchptr.add(7 + 8), weakStr);
Memory.writePointer(switchptr.add(7 + 15), strongStr);
Memory.writePointer(switchptr.add(7 + 22), awfulStr);
Memory.writePointer(switchptr.add(7 + 29), bossStr);

// Fix the jmptable so that people with similar cp show up as weak (otherwise
// they will skip over our strings).
var jmptable = Memory.readPointer(switchptr.add(3));

copy(jmptable.add(8), jmptable.add(4), 4);

protect(switchptr, 1000, p);

var createAltNameStr = scan('55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC 18 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 ?? ?? ?? ?? 8B F1 33 DB 89 5D E0');

Interceptor.attach(createAltNameStr, {
    onEnter(args) {
        // Follow through the execution of the function to find these offsets,
        // they are pretty easy to get.
        var thisPtr = this.context.ecx;
        var entPtr = Memory.readPointer(thisPtr.add(0x90));
        var cp = Memory.readFloat(entPtr.add(0x11c));

        Memory.writeUtf16String(weakestStr, cp.toFixed() + " <mini>WEAKEST </mini>");
        Memory.writeUtf16String(weakStr, cp.toFixed() + " <mini>WEAK </mini>");
        Memory.writeUtf16String(strongStr, cp.toFixed() + " <mini>STRONG </mini>");
        Memory.writeUtf16String(awfulStr, cp.toFixed() + " <mini>AWFUL </mini>");
        Memory.writeUtf16String(bossStr, cp.toFixed() + " <mini>BOSS </mini>");
    }
});

