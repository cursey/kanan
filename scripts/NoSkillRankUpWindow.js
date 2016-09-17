// Description:
// Skip the white popup window "You have reached Rank 1 Sharp Mind!" after ranking up a skill. (created by Step29)

var pattern1 = scan('8b f0 33 db 3b f3 75 16 32 c0');
var pattern2 = scan('e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 10 8b 35');

patch(pattern1.add(6), [0x90, 0x90]);
patch(pattern2.add(7), [0x90, 0xE9]);
