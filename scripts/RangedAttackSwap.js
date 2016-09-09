//Default Ranged Attack Swap

//Find mov eax,00005209
//That's the ranged attack skill ID to change.

//Uncomment the line for the skill you want.

var pattern = scan('B8 09 52 00 00 C3');
//patch(pattern.add(1), 0x0A, 0x52); //Magnum Shot
//patch(pattern.add(1), 0x0C, 0x52); //Arrow Revolver
//patch(pattern.add(1), 0x0E, 0x52); //Support Shot
//patch(pattern.add(1), 0x0F, 0x52); //Mirage Missile
//patch(pattern.add(1), 0xFB, 0x55); //Crash Shot
//patch(pattern.add(1), 0x14, 0x52); //Spider Shot
