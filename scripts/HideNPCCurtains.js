// Hide NPC Curtains During NPC Conversations And Cutscenes (Step29)

var pattern = scan('55 8b ec 8a 45 08 56 8b f1 38 06');

if (pattern == NULL)
	send('Failed to apply patch.');
else
{
	patch(pattern.add(0), 0xB0);
	patch(pattern.add(1), 0x00);
	patch(pattern.add(2), 0xC2);
	patch(pattern.add(3), 0x04);
	patch(pattern.add(4), 0x00);
	patch(pattern.add(5), 0x90);
	patch(pattern.add(6), 0x90);
	patch(pattern.add(7), 0x90);
	patch(pattern.add(8), 0x90);
	patch(pattern.add(9), 0x90);
	patch(pattern.add(10), 0x90);
}
