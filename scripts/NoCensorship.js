// Look for xrefs to the unicode string ***
// Should have two references in the same function.
// Change the obvious jz to jmp.

var pattern = scan('0F 84 ? ? ? ? 80 7D F3 00 0F 84 ? ? ? ? 85 D2');

patch(pattern, [0x90, 0xE9]);
