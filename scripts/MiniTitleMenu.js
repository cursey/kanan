// Description:
// Removes all unknown titles (???) in the title selection menu, effectively creating a minimal and organized list of titles. (created by Step29)

var pattern1 = scan('85 C0 0F 88 ?? ?? ?? ?? 83 F8 01 7E ?? 83 F8 02 0F 85 ?? ?? ?? ?? 8B 0D');

patch(pattern1.add(3), 0x8A);
patch(pattern1.add(11), 0x7A);
patch(pattern1.add(17), 0x84);
