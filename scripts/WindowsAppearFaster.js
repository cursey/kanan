// Description: 
// Skips the animation when opening interface windows, causing them to open instantly. (created by Step29)

var pattern1 = scan('74 6F E8 ?? ?? ?? ?? 85 C0 74 10');
var pattern2 = scan('8B 4D 18 6A 00 51 8B 8E');

patch(pattern1, 0xEB);
patch(pattern2, [0x31, 0xC9, 0x90]);
