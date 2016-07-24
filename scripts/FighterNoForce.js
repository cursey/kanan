// No Persistent Fighter Chain Popup (Rydian)

var pattern = scan('83 79 44 01 75 09 6A 00 6A 00 E8');

if (pattern == NULL)
	send('Failed to apply patch.');
else
	patch(pattern.add(4), 0xEB);
