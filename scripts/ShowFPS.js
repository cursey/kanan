// Description:
// Show clean FPS counter. (created by Licat)

var pattern = scan('8B F8 8B CE 89 BD DC F7 FF FF E8 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 8B 10 8B C8 8B 42 04 FF D0 84 C0 0F 84');
var pattern2 = scan('72 E3 8D 8D F0 F7 FF FF');
var pattern3 = scan('8D 95 E8 F7 FF FF 52 8D 85 EC F7 FF FF 50 8B CE C7 85 E8 F7 FF FF 0A 00 16 00');
var fpsStr = scan('25 00 64 00 20 00 66 00 72 00 61 00 6D 00 65 00 73 00 2F 00 73 00 65 00 63 00 2C 00');

patch(pattern.add(33), Array(6).fill(0x90));
patch(pattern2.add(2), [0xE9, 0xB2, 0x00, 0x00, 0x00, 0x90]);
patch(pattern3.add(24), [0x00]);
patch(pattern3.add(82), [0x39, 0xC0]);
patch(fpsStr, [0x46, 0x00, 0x50, 0x00, 0x53, 0x00, 0x3A, 0x00, 0x20, 0x00, 0x25, 0x00, 0x64, 0x00, 0x00, 0x00]);
