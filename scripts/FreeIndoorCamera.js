// Free Indoor Camera To Rotate Indoors (Step29)

var pattern = scan('57 8b 7d 08 0f 84 22 02 00 00');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(4), 0x90);
	patch(pattern.add(5), 0xE9);
}
