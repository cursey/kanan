//Description: 
//Override the meta/flashy byte of item color codes on render to stop them from flashing (created by Rydian)

//Walkthrough: 
//When items are equipped/rendered, the color codes are written elsewhere in
//memory for the model rendering code to pick up on.  Searching for color 1
//should find it, with colors 2 and 3 right after it.  This patch has additional
//code to detect hair items (yes, hair is an item) and try to avoid overwriting
//their first byte, which is the color ID (opposed to hex).

//The original code signature.
var thePatchLocation = scan('8B 10 89 57 1C 8B 50 04');

//The new code that'll be injected.
var thePatch = [
	0x51,								//push ecx						//Save and blank ecx for use.
	0x31, 0xC9,							//xor ecx,ecx					
	0x80, 0x78, 0x01, 0x00,				//cmp byte ptr [eax+01],00		//Check the bytes
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x02, 0x00,				//cmp byte ptr [eax+02],00		//to see if they match
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x03, 0x10,				//cmp byte ptr [eax+03],10		//hair IDs.
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x83, 0xF9, 0x03,					//cmp ecx,03					//See if ecx is 3 (all three bytes matched).
	0x59,								//pop ecx
	0x0F, 0x84, 0x0C, 0x00, 0x00, 0x00,	//je +C							//If so, skip the overwrite.
	0xC6, 0x40, 0x03, 0x00,				//mov byte ptr [eax+03],00		//If not, overwrite the flashy bytes.
	0xC6, 0x40, 0x07, 0x00,				//mov byte ptr [eax+07],00
	0xC6, 0x40, 0x0B, 0x00,				//mov byte ptr [eax+0B],00
	0x8B, 0x10,							//mov edx,[eax]					//Back to original code.
	0x89, 0x57, 0x1C					//mov [edi+1C],edx
];

//Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

//Debug message to show where the injection is.
dmsg(ourCodeLocation);
//Write our code to that location.
patch(ourCodeLocation, thePatch);

//Insert the jmp at the end of our code block back to the normal code.
//Same number as the bytes of code originally overwritten.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(5));

//Now our code block is all setup, just make the jmp at thePatchLocation to it.
//Same size as the bytes of code originally overwritten.
patch(thePatchLocation, Array(5).fill(0x90));
insertJmp(thePatchLocation, ourCodeLocation);
