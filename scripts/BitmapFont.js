// Bitmap patch reversed from Abyss
// All credit to Blade3575

var bm1 = scan('client.exe', '80 BF 88 00 00 00 00 57 74 0D');
Memory.writeU8(bm1.add(8), 0x90);
Memory.writeU8(bm1.add(9), 0x90);

var bm2 = scan('client.exe', '80 BE 88 00 00 00 00 74 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 75');
Memory.writeU8(bm2.add(22), 0xEB);
