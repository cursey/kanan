// Hide NPC Curtains During NPC Conversations And Cutscenes (Step29)

var pattern = scan('55 8b ec 8a 45 08 56 8b f1 38 06');

if (pattern == NULL)
	send('Failed to apply patch.');
else
	patch(pattern.add(0), [0xB0, 0x00, 0xC2, 0x04, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
