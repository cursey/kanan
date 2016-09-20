// Originally found in JAP.

// Swaps the default skill used when using ranged weapons. (created by Rydian)

// Configuration:
// Down below, uncomment the line for the skill you want Ranged Attack to be replaced as by removing the '//' at the beginning of the line.

// Walkthrough: 
// Find mov eax,00005209 
// That's the ranged attack skill ID to change. (21001)

var pattern = scan('B8 09 52 00 00 5F');
// patch(pattern.add(1), 0x0A, 0x52); //Magnum Shot
// patch(pattern.add(1), 0x0C, 0x52); //Arrow Revolver
// patch(pattern.add(1), 0x0E, 0x52); //Support Shot
// patch(pattern.add(1), 0x0F, 0x52); //Mirage Missile
// patch(pattern.add(1), 0xFB, 0x55); //Crash Shot
// patch(pattern.add(1), 0x14, 0x52); //Spider Shot
// patch(pattern.add(1), 0x16, 0x52); //Urgent Shot
