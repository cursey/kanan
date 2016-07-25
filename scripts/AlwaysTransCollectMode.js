// Transformation Mastery Collect Mode Always Enabled (Rydian)

var pattern = scan('38 5F 78 0F 84 C9 02 00 00 8B CE');

if (pattern == NULL)
	msg('Failed to apply patch.');
else
{
	patch(pattern.add(4), 0x85);
}
