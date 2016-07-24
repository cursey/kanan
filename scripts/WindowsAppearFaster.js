// Windows Appear Faster

var pattern1 = scan('56 8B F1 80 BE ?? ?? ?? ?? ?? 74 ?? E8');
var pattern2 = scan('89 86 ?? ?? ?? ?? 8b ?? ?? 6a 00');

if (pattern1 == NULL || pattern2 == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern1.add(10), 0xEB);
	patch(pattern2.add(6), [0x31, 0xC9, 0x90]);

	var pattern3 = scan('89 86 ?? ?? ?? ?? 8b ?? ?? 6a 00');

	if (pattern3 == NULL)
		send('Failed to apply patch.');
	else
		patch(pattern3.add(6), [0x31, 0xC9, 0x90]);
}
