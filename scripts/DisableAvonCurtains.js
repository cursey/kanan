// Removes the curtains from Avon missions. Credits: Iceling/Koorimio

var pattern = scan('0F 84 ? ? ? ? 8B 0E 6A ? 6A');
patch(pattern, [0x90, 0xE9]);
