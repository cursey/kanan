// Description:
// Fixes the issue that causes Elf characters with high latency to freeze in place while using the skill Ranged Attack. (created by Blade3575)

var pattern = scan('CC 55 8B EC 56 57 8B F9 8B 07 8B 50 04 FF D2 8B C8 E8');

patch(pattern.add(1), [0x32, 0xC0, 0xC2, 0x04, 0x00]);
