// Bitmap patch reversed from Abyss
// All credit to Blade35755

var bm1 = scan('80 BF 88 00 00 00 00 57 74 0D');
var bm2 = scan('80 BE 88 00 00 00 00 74 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 75');
var bm3 = scan('EB ?? 33 FF 8B 5D F8 83 BB A0 00 00 00 01 74');
var bm4 = scan('0F 84 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 56 3C 01 75');

if (bm1 == NULL || bm2 == NULL || bm3 == NULL || bm4 == NULL) {
    send('Failed to apply patch.');
}
else {
    patch(bm1.add(8), 0x90);
    patch(bm1.add(9), 0x90);

    patch(bm2.add(22), 0xEB);

    patch(bm3.add(14), 0xEB);

    patch(bm4, 0x90);
    patch(bm4.add(1), 0x90);
    patch(bm4.add(2), 0x90);
    patch(bm4.add(3), 0x90);
    patch(bm4.add(4), 0x90);
    patch(bm4.add(5), 0x90);
    patch(bm4.add(12), 0x90);
    patch(bm4.add(13), 0x90);
    patch(bm4.add(14), 0x90);
    patch(bm4.add(15), 0xB0);
    patch(bm4.add(16), 0x01);
    patch(bm4.add(21), 0xEB);
}
