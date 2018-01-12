//Description:
//Prevent the chat tab from changing to squad chat when you enter a squad. (created by Rydian)

//Walkthrough:
//Find the memory address that contains the current chat tab.
//In NA, the chat tab values are 0/2/4/5/6/7/8 (4byte).
//That's All, Party, Whisper, Guild, Trade, etc.
//When it's set to 8, reset it to 0 to avoid going to squad chat.

// The original code signature.
var thePatchLocation = scan('89 BE 58 01 00 00 8B 8C');

// The new code that'll be injected.
var thePatch = [
	0x83, 0xFF, 0x08,						//cmp edi,08
	0x0F, 0x85, 0x02, 0x00, 0x00, 0x00,		//jne nochange
	0x31, 0xFF,								//xor edi,edi
											//nochange:
	0x89, 0xBE, 0x58, 0x01, 0x00, 0x00		//mov [esi+00000158],edi
];

// Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

// Debug message to show where the injection is.
dmsg(ourCodeLocation);
// Write our code to that location.
patch(ourCodeLocation, thePatch);

//Insert the jmp at the end of our code block back to the normal code.
//Same number as the bytes of code originally overwritten.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(6));

//Now our code block is all setup, just make the jmp at thePatchLocation to it.
//Same size as the bytes of code originally overwritten.
patch(thePatchLocation, Array(6).fill(0x90));
insertJmp(thePatchLocation, ourCodeLocation);
