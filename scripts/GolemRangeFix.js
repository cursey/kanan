// When controling a Golem, disable changing control to the character when out of range.

var pattern = scan('84 C0 0F 84 1F 05 00 00 8B 4E 28');
patch(pattern.add(3), 0x81);
