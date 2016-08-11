// Hide titles of all players (Rydian).

var pattern = scan('08 00 66 8b 41 10 C3');

patch(pattern.add(2), [0x31, 0xC0, 0x90, 0x90]);
