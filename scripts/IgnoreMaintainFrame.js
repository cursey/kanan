// Originally found in JinsuNogi.

// Description:
// Ignore the maintain frame setting during character minimization. (created Rydian)

// Walkthrough: 
// When you change the framerate and save the options screen,
// the game writes the value somewhere.  This is a different
// address than the temporary one it uses while in the options.
// Change this operation to load from ebp, which holds an
// address, which will be a value much larger than the FPS we
// can ever obtain in Mabinogi, because it runs like crap.
//
// 89 4E 50              - mov [esi+50],ecx
// Becomes
// 89 6E 50              - mov [esi+50],ebp

var pattern = scan('89 4E 50 8B 57 54 89 56 54 0F B6 47 58 88 46 58 0F B6 4F 59');

patch(pattern.add(1), [0x6E]);
