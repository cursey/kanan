// NPC Fast Text

var pattern = scan('client.exe', '8B 08 33 FF 3B CF 76 2A');

if (debug)
	send(pattern);

if (pattern == NULL)
	send('Failed to apply patch.');
else
	patch(pattern.add(6), 0xEB);
