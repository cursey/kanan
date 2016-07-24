// Objects Between Camera and Character Do Not Become Transparent (Rydian)

var pattern = scan('39 70 04 75 39 3B FE');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(3), 0x90);
	patch(pattern.add(4), 0x90);
}
