// Gives You DevCat Title To See Extra Information In Various Places (Rydian)

var pattern = scan('08 00 66 8B 41 10 C3');

if (pattern == NULL)
	msg('Failed to apply patch.');
else
	patch(pattern.add(3), [0xB8, 0x61, 0xEA]);
