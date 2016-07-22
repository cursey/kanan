// Elf Lag Fix

var pattern = scan('CC 55 8B EC 56 57 8B F9 8B 07 8B 50 04 FF D2 8B C8 E8');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(1), 0x32);
	patch(pattern.add(2), 0xC0);
	patch(pattern.add(3), 0xC2);
	patch(pattern.add(4), 0x04);
	patch(pattern.add(5), 0x00);
}
