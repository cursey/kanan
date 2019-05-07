// Description:
// Skips the animation when opening interface windows, causing them to open instantly. (created by Step29)

var pattern1 = scan('74 ? E8 ? ? ? ? 85 C0 74 ? F6 46 14 ? 75 ? 8B 10 8B C8 8B 82 78 01 00 00 FF D0 84 C0 75 ? 83 BE A8 00 00 00 ? C6 86 A4 00 00 00 ? 75 ? B9 ? ? ? ? E8 ? ? ? ? 89 86 A8 00 00 00 8B 4D 08');
var pattern2 = scan('8B 4D 18 6A ? 51 8B 8E A8 00 00 00');

patch(pattern1, 0xEB);
patch(pattern2, [0x31, 0xC9, 0x90]);
