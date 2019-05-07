// Description:
// Fixes the issue that causes Elf characters with high latency to freeze in place while using the skill Ranged Attack. (created by Blade3575)

var pattern = scan('55 8B EC 56 8B F1 8B 06 8B 50 0C 57 FF D2 8B C8');
patch(pattern, [0x32, 0xC0, 0xC2, 0x04, 0x00]);
