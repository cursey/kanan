//No Render Sky (Step29)

var NoSky1 = scan('74 42 8B 4E 04 8B 11 8B 82 E4 00 00 00 6A 04 FF D0 8B C8 E8');
var NoSky2 = scan('8B 4E 30 85 C9 0F 84 91 00 00 00 E8');

patch(NoSky1,0xEB);
patch(NoSky2.add(5), [0x90, 0xE9]);
