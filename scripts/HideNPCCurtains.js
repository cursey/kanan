// Description: 
// Hide the black border curtains at the top and bottom of the screen while talking to NPCs, viewing a cutscene or using a moon gate. (created by Step29)

var pattern = scan('55 8b ec 8a 45 08 56 8b f1 38 06');

patch(pattern.add(0), [0xB0, 0x00, 0xC2, 0x04, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
