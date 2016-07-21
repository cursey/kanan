// Bitmap patch reversed from Abyss
// All credit to Blade3575

var bm1 = moduleOffset('client.exe', 0xb55cef);
var bm2 = moduleOffset('client.exe', 0xcab100);
var bm3 = moduleOffset('client.exe', 0xc1a4b3);
var bm4 = moduleOffset('client.exe', 0xb8e4b3);

if (debug) {
    send(bm1);
    send(bm2);
    send(bm3);
    send(bm4);
}

if (bm1 == NULL || bm2 == NULL || bm3 == NULL || bm4 == NULL)
	send('Failed to apply patch.');
else
{
	patch(bm1.add(8), 0x90);
	patch(bm1.add(9), 0x90);

	patch(bm2.add(22), 0xEB);

    patch(bm3.add(14), 0xEB);

    patch(bm4, 0x90);
    patch(bm4.add(1), 0x90);
    patch(bm4.add(2), 0x90);
    patch(bm4.add(3), 0x90);
    patch(bm4.add(4), 0x90);
    patch(bm4.add(5), 0x90);
    patch(bm4.add(12), 0x90);
    patch(bm4.add(13), 0x90);
    patch(bm4.add(14), 0x90);
    patch(bm4.add(15), 0xB0);
    patch(bm4.add(16), 0x01);
    patch(bm4.add(21), 0xEB);
}
