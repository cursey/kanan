// Description: 
// Stops all objects from loading. (created by Poshwosh)

var pattern = scan('39 78 0C 0F 94 C0 84 C0 0F 84 92 00 00 00 8B 45');
patch(pattern.add(8), [0x90,0xE9]);
