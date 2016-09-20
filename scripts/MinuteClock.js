// Originally found in Fantasia.

// Description: 
// Updates the clock on a 1 minute basis as opposed to 10 minutes.

// Walkthrough:
// From data/code/interface.english.txt look for A.M. (as it appears in the
// clock).  Gives us the following string.
// IDA unicode string view -> code.interface.window.clock.am
// xrefs
// Its referenced in two functions multiple times. Since we don't know which one
// (or both) is the one we are interestead in, put a BP on both in CE.
// Only one gets called, thats the one we reverse.
// In graph view, scrolling up twoards the top of the function we see a basic
// block that has 4 paths leading to it. This basic block should stick out for
// another reason, it looks suspiciously like magic number division.
// In this case, thats exactly what it is, with the magic number being CCCCCCCDh
//
// From http://www.hackersdelight.org/magic.htm we can see that the divisor 10
// coincides with that magic number, as does the right-shift by 3 that we also
// see in the basic block.
//
// All we do is nop the magic division and we get a clock that updates every
// minute instead of every 10 minutes.
//
// After testing my friend told me the 24 hour clock is not updating every
// minute like the 12 hour clock is. Within the same function we can see the
// exact same magic number division happen further down in the function.
// Nopping that block as well enables minute updates for the 24 hour clock.
//
// Instead of nopping the entire division we can just nop the mov that stores
// the result. This gives us simpler patterns and patches.

var mov1 = scan('89 4D C4 39 9F');
var mov2 = scan('89 55 C4 39 9F');

patch(mov1, [0x90, 0x90, 0x90]);
patch(mov2, [0x90, 0x90, 0x90]);
