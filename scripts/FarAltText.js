// Originally found in JAP by kotarou3.

// Description:
// Allows you to see entities while holding down ALT from much further away.

// Walkthrough:
// Search for a static 3000.0 (there will be more than one so try until you
// are certain you found the right one).
// Find what accesses it
// Look for an fld [<address>] that is called a ton
// nop the jnz.

var pattern = scan('0F 85 ?? ?? ?? ?? D9 EE D9 45 D4');
patch(pattern, Array(6).fill(0x90));
