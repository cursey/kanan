// Description:
// Removes the "Obtained X item" reward window that shows up when acquiring items, stats or exp. (created by Licat)

var pattern = scan('39 5D 14 0F 85 ?? ?? ?? ?? 8D 4D EC');

patch(pattern, [0x90, 0x39, 0xDB, 0x0f, 0x84]);
