// NPC Fast Text

var pattern = scan('8B 08 33 FF 3B CF 76 2A');

if (pattern == NULL)
	msg('Failed to apply patch.');
else
	patch(pattern.add(6), 0xEB);
