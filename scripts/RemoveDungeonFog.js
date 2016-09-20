// Originally found in JAP.

// Description:
// Remove the fog on the map while in dungeons, automatically unveiling them. (created by ???)

var pattern = scan('0F B6 41 05 C1 E8 02 83 E0 01 C3');
patch(pattern.add(0), [0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
