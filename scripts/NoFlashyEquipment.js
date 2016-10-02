//Description: 
//Override the meta/flashy byte of item color codes on render to stop them from flashing (created by Rydian)

//Walkthrough: 
//When items are equipped/rendered, the color codes are written elsewhere in
//memory for the model rendering code to pick up on.  Searching for color 1
//should find it, with colors 2 and 3 right after it.  This patch has additional
//code to detect hair items (yes, hair is an item) and try to avoid overwriting
//their first byte, which is the color ID (opposed to hex).

// The original code signature.
var thePatchLocation = scan('8B 10 89 57 1C 8B 50 04');

// The new code that'll be injected.
var thePatch = [
	0x51,								//push ecx
	0x31, 0xC9,							//xor ecx,ecx
	0x80, 0x78, 0x01, 0x00,				//cmp byte ptr [eax+01],00
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x02, 0x00,				//cmp byte ptr [eax+02],00
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x03, 0x10,				//cmp byte ptr [eax+03],10
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x83, 0xF9, 0x03,					//cmp ecx,03
	0x59,								//pop ecx
	0x0F, 0x84, 0x61, 0x00, 0x00, 0x00,	//je skipoverwrite
	0x51,								//push ecx
	0x31, 0xC9,							//xor ecx,ecx
	0x80, 0x78, 0x03, 0x00,				//cmp byte ptr [eax+03],00
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x03, 0xFF,				//cmp byte ptr [eax+03],FF
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x83, 0xF9, 0x00,					//cmp ecx,00
	0x75, 0x0A,							//jne +A
	0x52,								//push edx
	0x8A, 0x10,							//mov dl,[eax]
	0x88, 0x50, 0x01,					//mov [eax+01],dl
	0x88, 0x50, 0x02,					//mov [eax+02],dl
	0x5A,								//pop edx
	0x31, 0xC9,							//xor ecx,ecx
	0x80, 0x78, 0x07, 0x00,				//cmp byte ptr [eax+07],00
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x07, 0xFF,				//cmp byte ptr [eax+07],-01
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x83, 0xF9, 0x00,					//cmp ecx,00
	0x75, 0x0B,							//jne +B
	0x52,								//push edx
	0x8A, 0x50, 0x04,					//mov dl,[eax+04]
	0x88, 0x50, 0x05,					//mov [eax+05],dl
	0x88, 0x50, 0x06,					//mov [eax+06],dl
	0x5A,								//pop edx
	0x31, 0xC9,							//xor ecx,ecx
	0x80, 0x78, 0x0B, 0x00,				//cmp byte ptr [eax+0B],00
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x80, 0x78, 0x0B, 0xFF,				//cmp byte ptr [eax+0B],FF
	0x75, 0x01,							//jne +1
	0x41,								//inc ecx
	0x83, 0xF9, 0x00,					//cmp ecx,00
	0x75, 0x0B,							//jne +B
	0x52,								//push edx
	0x8A, 0x50, 0x08,					//mov dl,[eax+08]
	0x88, 0x50, 0x09,					//mov [eax+09],dl
	0x88, 0x50, 0x0A,					//mov [eax+0A],dl
	0x5A,								//pop edx
	0x59,								//pop ecx
										//skipoverwrite:
	0x8B, 0x10,							//mov edx,[eax]
	0x89, 0x57, 0x1C,					//mov [edi+1C],edx
];

// Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

// Debug message to show where the injection is.
dmsg(ourCodeLocation);
// Write our code to that location.
patch(ourCodeLocation, thePatch);

//Insert the jmp at the end of our code block back to the normal code.
//Same number as the bytes of code originally overwritten.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(5));

//Now our code block is all setup, just make the jmp at thePatchLocation to it.
//Same size as the bytes of code originally overwritten.
patch(thePatchLocation, Array(5).fill(0x90));
insertJmp(thePatchLocation, ourCodeLocation);


//This is a copy of the original CE injection, with original comments.
/*
  //Check to make sure the color id for 1 isn't xx000010 which is usually hair.
  //We don't want to overwrite that byte in that case.

  //Save and blank ecx for use.
  push ecx
  xor ecx,ecx

  //Check the normal bytes and inc ecx if they're 00.
  cmp byte [eax+1],00
  jne short +1
  inc ecx
  cmp byte [eax+2],00
  jne short +1
  inc ecx
  cmp byte [eax+3],10
  jne short +1
  inc ecx
  //+4 is the first byte due to x86 being annoying.

  //See if ecx is 3 (so all three bytes matched hair).
  cmp ecx,3
  //Restore ecx now that we're done.
  pop ecx
  //If all three bytes matched hair, skip the overwrite.
  je skipoverwrite

  //Now check if the code has flashy bytes at all.
  push ecx

  xor ecx,ecx
  //Check color 1's flashy byte for 00 or FF.
  cmp byte [eax+3],00
  jne short +1
  inc ecx
  cmp byte [eax+3],FF
  jne short +1
  inc ecx
  //If ecx is not 0 (so it's one of those), skip overwrite.
  cmp ecx,0
  jne short +A //This jump is one byte shorter, first byte has no offset.
  //Overwrite color 1's color indexes.  DL is the low byte of edx.
  push edx
  mov dl,[eax]
  mov [eax+01],dl
  mov [eax+02],dl
  pop edx

  xor ecx,ecx
  //Check color 1's flashy byte for 00 or FF.
  cmp byte [eax+7],00
  jne short +1
  inc ecx
  cmp byte [eax+7],FF
  jne short +1
  inc ecx
  //If ecx is not 0 (so it's one of those), skip overwrite.
  cmp ecx,0
  jne short +B
  //Overwrite color 2's color indexes.  DL is the low byte of edx.
  push edx
  mov dl,[eax+04]
  mov [eax+05],dl
  mov [eax+06],dl
  pop edx

  xor ecx,ecx
  //Check color 1's flashy byte for 00 or FF.
  cmp byte [eax+B],00
  jne short +1
  inc ecx
  cmp byte [eax+B],FF
  jne short +1
  inc ecx
  //If ecx is not 0 (so it's one of those), skip overwrite.
  cmp ecx,0
  jne short +B
  //Overwrite color 2's color indexes.  DL is the low byte of edx.
  push edx
  mov dl,[eax+08]
  mov [eax+09],dl
  mov [eax+0A],dl
  pop edx

  //Restore ecx now that we're done with it.
  pop ecx

skipoverwrite:
  mov edx,[eax] //Back to the original code.
  mov [edi+1C],edx
  jmp return
*/
