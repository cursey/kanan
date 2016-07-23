// Hide Second Titles Of All Players (Step29)

var pattern = scan('c1 e9 14 f6 c1 01 75 ?? 8b');

if (pattern == NULL)
	send('Failed to apply patch.');
else
	patch(pattern.add(6), 0xEB);
