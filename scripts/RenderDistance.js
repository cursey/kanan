// Description:
// Override and increase the Range of Vision value in the Options menu to render more from distance. (created by Rydian)

// Configuration:
// Set this to your desired range of vision. For reference, Dunbarton maxes out at 15000.
var desiredRangeOfVision = 30000.0;

// Walkthrough:
// This is the target location we will patch (hook at).
// There's an fld [ebp+0Ch] which is followed by fst [esi+40h]. We want to overwrite
// the fst, but do not have enough bytes to do so so we'll copy the relevant code
// to a new block of memory, insert our modifications, then jump back.
var thePatchLocation = scan('D9 45 0C D9 56 40');

// These are the bytes inserted at the new memory.
// Our patch is going to include the original fld and fst instructions, but then
// effectively overwrite the result by moving the hex representation of our
// desired floating point value to esi+40h.
var thePatch = [
    0xD9, 0x45, 0x0C, 0xD9, 0x56, 0x40, 0xC7, 0x46, 0x40, 0xFF, 0xFF, 0xFF, 0xFF
];

// Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

// Debug message to show where the injection is.
dmsg(ourCodeLocation);
// Write our code to that location.
patch(ourCodeLocation, thePatch);

// Replace the placeholder 0xFFFFFFFF with the desired range of vision.
patchFloat(ourCodeLocation.add(9), desiredRangeOfVision);

// Insert the jmp at the end of our code block back to the normal code.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(6));

// Now our code block is all setup, just make the jmp at thePatchLocation to it.
patch(thePatchLocation, Array(6).fill(0x90)); // 2 instructions take up 6 bytes.
insertJmp(thePatchLocation, ourCodeLocation);
