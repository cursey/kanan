// Bitmap patch reversed from Abyss
// All credit to Blade3575

var bm1 = moduleOffset('client.exe', ptr('0xb55cef'));
var bm2 = moduleOffset('client.exe', ptr('0xcab100'));

if (debug) {
    send(bm1);
    send(bm2);
}

if (bm1 == NULL || bm2 == NULL)
	send('Failed to apply patch.');
else
{
	patch(bm1.add(8), 0x90);
	patch(bm1.add(9), 0x90);

	patch(bm2.add(22), 0xEB);
}
