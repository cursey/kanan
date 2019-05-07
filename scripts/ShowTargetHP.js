// Targets will show their HP / Max HP under their HP bar.

var pattern = scan('68 F8 03 00 00 89 5D');
patch(pattern.add(-12), [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
