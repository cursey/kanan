// One Click Revive

var pattern = scan('39 ?? ?? 0F 86 ?? ?? ?? ?? 8B ?? ?? 8B 11');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(3), 0x90);
	patch(pattern.add(4), 0xE9);
}
