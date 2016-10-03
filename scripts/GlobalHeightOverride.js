//Description: 
//Override the height (or age) of every character including players, pets, enemies and NPCs. (created by Rydian)
//This affects all player races (human/elf/giant).  It will affect NPCs that are the same race.
//It's designed to avoid changing pets/monsters by comparing racial IDs.

//Configuration:
//1.0 = Normal
//0.2 = Child
//-0.4 = Tin Potion
var desiredHeight = -0.4;

//Walkthrough: 
//Find the fld that loads an entity's height value (+88)
//when it comes into render distance or changes stats/looks.
//We want to inject code to overwrite this read.

//In decimal...
//10001 = Human Female
//10002 = Human Male
//8001 = Giant Female
//8002 = Giant Male
//9001 = Elf Female
//9002 = Elf Male

//The original code signature.
var thePatchLocation = scan('D9 81 88 00 00 00 C3 CC CC CC CC CC CC CC CC CC D9');

//The new code that'll be injected.
var thePatch = [
	0x53,                                        //push ebx						//Save EBX on the stack so we can safely use it.
	0x31, 0xDB,                                  //xor ebx,ebx					//Blank EBX so we can use it as a counter.
	0x81, 0x79, 0x38, 0x11, 0x27, 0x00, 0x00,    //cmp [ecx+38],2711			//Human female check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x81, 0x79, 0x38, 0x12, 0x27, 0x00, 0x00,    //cmp [ecx+38],2712			//Human male check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x81, 0x79, 0x38, 0x41, 0x1F, 0x00, 0x00,    //cmp [ecx+38],1F41			//Giant female check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x81, 0x79, 0x38, 0x42, 0x1F, 0x00, 0x00,    //cmp [ecx+38],1F42			//Giant male check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x81, 0x79, 0x38, 0x29, 0x23, 0x00, 0x00,    //cmp [ecx+38],2329			//Elf female check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x81, 0x79, 0x38, 0x2A, 0x23, 0x00, 0x00,    //cmp [ecx+38],232A			//Elf male check.
	0x75, 0x01,                                  //jne short +1					//If false, skip the next increment.
	0x43,                                        //inc ebx
	0x83, 0xFB, 0x00,                            //cmp ebx,0					//Check if EBX has been incremented or not.
	0x5B,                                        //pop ebx						//Restore EBX now that we're done using it.
	0x74, 0x0D,                                  //je short +D					//If it has not been incremented, skip past the custom code.
	0x50,                                        //push eax						//Store the current value of EAX onto the stack.
	0xB8, 0x00, 0x00, 0x1D, 0x08,			//mov eax,(Float)1.0			//Move the user value into EAX (placeholder at this point).
	0x89, 0x81, 0x88, 0x00, 0x00, 0x00,          //mov [ecx+00000088], eax		//Copy that value into the structure.
	0x58,                                        //pop eax						//Restore EAX.
	0xD9, 0x81, 0x88, 0x00, 0x00, 0x00,          //fld dword ptr [ecx+00000088]	//Original code.
];  
    
// Allocate 5 extra bytes beyond the above to fit the jmp back to normal code.
var ourCodeLocation = allocateMemory(thePatch.length + 5);

// Debug message to show where the injection is.
dmsg(ourCodeLocation);
// Write our code to that location.
patch(ourCodeLocation, thePatch);

// Replace the placeholder value with the desired value.
patchFloat(ourCodeLocation.add(71), desiredHeight);

// Insert the jmp at the end of our code block back to the normal code.
insertJmp(ourCodeLocation.add(thePatch.length), thePatchLocation.add(6));

// Now our code block is all setup, just make the jmp at thePatchLocation to it.
patch(thePatchLocation, Array(6).fill(0x90)); // 2 instructions take up 6 bytes.
insertJmp(thePatchLocation, ourCodeLocation);
