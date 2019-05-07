// Description:
// Skip the white popup window "You have reached Rank 1 Sharp Mind!" after ranking up a skill. (created by Step29)

var pattern1 = scan('8B F0 33 DB 3B F3 75 16 32 C0');
var pattern2 = scan('E8 ? ? ? ? 85 C0 0F 84 ? ? ? ? 8B 10 8B 35');

patch(pattern1.add(6), [0x90, 0x90]);
patch(pattern2.add(7), [0x90, 0xE9]);
