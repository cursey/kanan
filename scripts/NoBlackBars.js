// No Black Bars At Edges Of Screen Or Windows (Rydian)

var pattern = scan('client.exe', '8B 8E F8 00 00 00 85 C9 74 07 6A 01 E8 ?? ?? ?? ?? 8B 0D');

if (debug)
	send(pattern);

if (pattern == NULL)
	send('Failed to apply patch.');
else
	patch(pattern.add(11), 0x01);
