// No Skill Rank Up Window (Step29)

var pattern1 = scan('8b f0 33 db 3b f3 75 16 32 c0');
var pattern2 = scan('e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 10 8b 35');

if (pattern1 == NULL || pattern2 == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern1.add(6), 0x90);
	patch(pattern1.add(7), 0x90);
	patch(pattern1.add(7), 0x90);
	patch(pattern2.add(8), 0xE9);
}
