// This script lets you cancle lance counter once its been loaded.

// This was just updated from an old patchers source code (JAP).

// The function references the string: LIMIT_T
// It is not the only function that references LIMIT_T but it is one of three.
// The other two functions that reference LIMIT_T also reference other strings
// so find the function that only references LIMIT_T.
// Make it return 1.

var pattern = scan('55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC 0C 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 ? ? ? ? E8 ? ? ? ? 84 C0 0F 84');

patch(pattern, [ 0xB0, 0x01, 0xC2, 0x04, 0x00 ]);
