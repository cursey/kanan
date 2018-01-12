// Description:
// Removes the "Obtained X item" reward window that shows up when acquiring items, stats or exp. (created by Licat)

var pattern = scan('3B D6 0F 85 ?? ?? ?? ?? 33 DB');

patch(pattern, [0x39, 0xDB, 0x0f, 0x84]);
