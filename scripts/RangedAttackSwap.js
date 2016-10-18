// Originally found in JAP.

// Swaps the default skill used when using ranged weapons. (created by Rydian)

// Configuration:
// Use the config.toml file.

// Walkthrough:
// Find mov eax,00005209
// That's the ranged attack skill ID to change. (21001)

var swappedSkill = getConfigValue('swapped_skill', 0);
var pattern = scan('B8 09 52 00 00 5F');

switch (swappedSkill) {
case 1: patch(pattern.add(1), 0x0A, 0x52); break; //Magnum Shot
case 2: patch(pattern.add(1), 0x0C, 0x52); break; //Arrow Revolver
case 3: patch(pattern.add(1), 0x0E, 0x52); break; //Support Shot
case 4: patch(pattern.add(1), 0x0F, 0x52); break; //Mirage Missile
case 5: patch(pattern.add(1), 0xFB, 0x55); break; //Crash Shot
case 6: patch(pattern.add(1), 0x14, 0x52); break; //Spider Shot
case 7: patch(pattern.add(1), 0x16, 0x52); break; //Urgent Shot
}
