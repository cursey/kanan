// Remove the Nexon survey window after closing the game. Credits: Rotar

var pattern = scan('50 8B 45 D0 50 51 56 FF 15');
patch(pattern.add(7), [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
