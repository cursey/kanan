//Global height override (Rydian)

//Find the fld that loads an entity's height value (+88)
//when it comes into render distance or changes stats/looks.
//Overwrite that with an fld1 to always load a standard height.

var pattern = scan('D9 81 88 00 00 00 C3 CC CC CC CC CC CC CC CC CC D9');

patch(pattern.add(0), [0xD9, 0xE8, 0x90, 0x90, 0x90, 0x90]);
