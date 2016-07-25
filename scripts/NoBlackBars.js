// No Black Bars At Edges Of Screen Or Windows (Rydian)

var pattern = scan('8B 8E F8 00 00 00 85 C9 74 07 6A 01 E8 ?? ?? ?? ?? 8B 0D');

if (pattern == NULL)
	msg('Failed to apply patch.');
else
	patch(pattern.add(11), 0x01);
