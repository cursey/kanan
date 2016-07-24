// Fixes Mana Tunnel Lag By Removing Position Marker (Step29)

var pattern = scan('4D 00 79 00 50 00 6F 00 73 00 69 00 74 00 69 00 6F 00 6E 00 4D 00 61 00 72 00 6B 00 65 00 72 00 49 00 6D 00 61 00 67 00 65 00');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(0), 0x00);
	patch(pattern.add(1), 0x00);
	patch(pattern.add(2), 0x00);
	patch(pattern.add(3), 0x00);
	patch(pattern.add(4), 0x00);
	patch(pattern.add(5), 0x00);
	patch(pattern.add(6), 0x00);
	patch(pattern.add(7), 0x00);
	patch(pattern.add(8), 0x00);
	patch(pattern.add(9), 0x00);
	patch(pattern.add(10), 0x00);
	patch(pattern.add(11), 0x00);
	patch(pattern.add(12), 0x00);
	patch(pattern.add(13), 0x00);
	patch(pattern.add(14), 0x00);
	patch(pattern.add(15), 0x00);
	patch(pattern.add(16), 0x00);
	patch(pattern.add(17), 0x00);
	patch(pattern.add(18), 0x00);
	patch(pattern.add(19), 0x00);
	patch(pattern.add(20), 0x00);
	patch(pattern.add(21), 0x00);
	patch(pattern.add(22), 0x00);
	patch(pattern.add(23), 0x00);
	patch(pattern.add(24), 0x00);
	patch(pattern.add(25), 0x00);
	patch(pattern.add(26), 0x00);
	patch(pattern.add(27), 0x00);
	patch(pattern.add(28), 0x00);
	patch(pattern.add(29), 0x00);
	patch(pattern.add(30), 0x00);
	patch(pattern.add(31), 0x00);
	patch(pattern.add(32), 0x00);
	patch(pattern.add(33), 0x00);
	patch(pattern.add(34), 0x00);
	patch(pattern.add(35), 0x00);
	patch(pattern.add(36), 0x00);
	patch(pattern.add(37), 0x00);
	patch(pattern.add(38), 0x00);
	patch(pattern.add(39), 0x00);
	patch(pattern.add(40), 0x00);
	patch(pattern.add(41), 0x00);
}
