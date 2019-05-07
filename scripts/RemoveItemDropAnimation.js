// Removes item drop animations.

var pattern = scan('0F 84 17 02 00 00 39 9E');
patch(pattern, [0x90, 0xE9]);
