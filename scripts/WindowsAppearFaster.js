// Windows Appear Faster

var pattern1 = scan('client.exe', '56 8B F1 80 BE ?? ?? ?? ?? ?? 74 ?? E8');
var pattern2 = scan('client.exe', '89 86 ?? ?? ?? ?? 8b ?? ?? 6a 00');

if (debug)
{
	send(pattern1);
	send(pattern2);
}

if (pattern1 == NULL || pattern2 == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern1.add(10), 0xEB);
	patch(pattern2.add(6), 0x31);
	patch(pattern2.add(7), 0xC9);
	patch(pattern2.add(8), 0x90);

	var pattern3 = scan('client.exe', '89 86 ?? ?? ?? ?? 8b ?? ?? 6a 00');

	if (debug)
		send(pattern3);

	if (pattern3 == NULL)
		send('Failed to apply patch.');
	else
	{
		patch(pattern3.add(6), 0x31);
		patch(pattern3.add(7), 0xC9);
		patch(pattern3.add(8), 0x90);
	}
}
