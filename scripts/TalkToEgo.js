// Originally found in JinsuNogi.

//Talk to unequipped ego (by Rydian).

//"Please equip the spirit weapon-"

//Find code.client.msg.equip_ego_weapon in memory, unicode.
//Find the address it's at.  There will be a push of that.
//If it's at 029B3CD8, then the push would be 68 D83C9B02.
//(Reverse byte order.)  If multiple results, guess and test.

//The push sets stuff up to give you the error message,
//so we'll change the jne right above it to not go down that
//path and let you actually talk to the ego.

var pattern = scan('0F 85 8F 00 00 00 68 D8 3C 9B 02');

patch(pattern.add(0), [0x90, 0xE9]);
