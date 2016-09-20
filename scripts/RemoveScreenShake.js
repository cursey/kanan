// Originally found in Abyss by Blade3575.

// Description: 
// Stops the screen from shaking when using Fireball, summoning a dragon, etc.

// Walkthrough: 
// Intuition: A timer is started at the beginning of a screen shake.
// So to find the function responsible for screen shake simply start searching
// for an unknown 4 byte value (mabi uses timeGetTime() for timing it seems).
// Then force your screen to shake by summoning a pet or however you want and
// search again for an increased value. Continue until you have only a few
// values left. You should be able to find the one representing the start time
// of the screen shake fairly easily.
//
// You can test that you have the right value by freezing it and noticing that
// when a new screen shake occures, it is ended abruptly.
//
// Find out what writes to the value by forcing a screen shake.  You should find
// a relativley small function that does some floating point loads and stores
// near the bottom.  This is the screen shake function.
//
// A simple way to remove the screen shake from this function is to change all
// the fld -> fldz

var firstFld = scan('D9 01 8B 46 64');

patch(firstFld, [0xD9, 0xEE]);
patch(firstFld.add(9), [0xD9, 0xEE, 0x90]);
patch(firstFld.add(15), [0xD9, 0xEE, 0x90]);
patch(firstFld.add(21), [0xD9, 0xEE, 0x90]);


