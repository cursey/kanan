// Description: 
// Override the height (or age) of every character including players, pets, enemies and NPCs. (created by Rydian)

// Configuration:
// 1.0 = Normal
// 0.2 = Child
// -0.4 = Tin Potion
var desiredHeight = -0.4;

// Walkthrough: 
// Find the fld that loads an entity's height value (+88)
// when it comes into render distance or changes stats/looks.
// We want to inject code to overwrite this read.

// The original code signature.
var thePatchLocation = scan('D9 81 88 00 00 00 C3 CC CC CC CC CC CC CC CC CC D9');

// The new code that'll be injected.
var thePatch = [
	0x50,							// push eax
	0xB8, 0x00, 0x00, 0x1D, 0x08,				// mov eax,081D0000
	0x89, 0x81, 0x88, 0x00, 0x00, 0x00,			// mov [ecx+00000088],eax
	0x58,							// pop eax
	0xD9, 0x81, 0x88, 0x00, 0x00, 0x00			// fld dword ptr [ecx+00000088]
];

// Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

// Debug message to show where the injection is.
dmsg(ourCodeLocation);
// Write our code to that location.
patch(ourCodeLocation, thePatch);

// Replace the placeholder value with the desired value.
patchFloat(ourCodeLocation.add(2), desiredHeight);

// Insert the jmp at the end of our code block back to the normal code.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(6));

// Now our code block is all setup, just make the jmp at thePatchLocation to it.
patch(thePatchLocation, Array(6).fill(0x90)); // 2 instructions take up 6 bytes.
insertJmp(thePatchLocation, ourCodeLocation);
