var pattern1 = scan('74 6F E8 ?? ?? ?? ?? 85 C0 74 10');
var pattern2 = scan('8B 4D 18 6A 00 51 8B 8E');

if (pattern1.isNull()) {
    msg("Failed to apply patch.");
}
else {
    patch(pattern1, 0xEB);
    patch(pattern2, [0x31, 0xC9, 0x90]);
}
