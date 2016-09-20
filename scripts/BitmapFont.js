// Originally found in Fantasia by spr33.

// Description:
// Reduces font size to bitmap-size, close to 8px in size. (created by Blade3575)

var bm1 = scan('80 BF 88 00 00 00 00 57 74 0D');
var bm2 = scan('80 BE 88 00 00 00 00 74 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 75');
var bm3 = scan('EB ?? 33 FF 8B 5D F8 83 BB A0 00 00 00 01 74');
var bm4 = scan('0F 84 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 3C 01 75');

patch(bm1.add(8), [0x90, 0x90]);
patch(bm2.add(22), 0xEB);
patch(bm3.add(14), 0xEB);
patch(bm4, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, -1, -1, -1, -1, -1, -1, 0x90, 0x90, 0x90, 0xB0, 0x01, -1, -1, -1, -1, 0xEB]);
