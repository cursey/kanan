// This script prevents the camera from being zoomed in when talking to your
// partners.

// The address we are patching is the fstp [esi+1Ch] described in
// FreeZoom.js

// Hideous pattern...
var theFstp = scan('D9 5E 1C E8 ? ? ? ? 8B 0E 8B 01 83 C4 04 3B C1 74 1B 8B 48 04 8B 10 89 11 8B 08 8B 50 04 50 89 51 04 E8 ? ? ? ? 83 C4 04 FF 4E 04 88 5E 10 39 5E 04 0F 85 ? ? ? ? D9 45 08');

// Our patch will replace the fstp but also the call that immediately follows
// it so we need to keep the address thats being called so we can do the call
// ourselves in our patch.
var theCall = theFstp.add(3);
var theCallAddress = calcAbsAddress(theCall); 

// We will be comparing against this value in our patch.
var float100 = allocateMemory(4);

patchFloat(float100, 100);

// Our patch which compares the zoom value thats trying to be set to 100 which 
// is the zoom value that is set when talking to a partner. If the zoom value
// being set is 100, we simply skip the instruction that sets the zoom.
var thePatch = [
    0x50,                           // push eax;
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF,   // mov eax, 0xFFFFFFFF; placeholder for float100
    0xD9, 0x00,                     // fld [eax];
    0x58,                           // pop eax;
    0xDF, 0xF1,                     // fcomip st, st(1);
    0x74, 0x05,                     // jz popfloat;
    0xD9, 0x5E, 0x1C,               // fstp [esi+0x1c]; the original instruction.
    0xEB, 0x02,                     // jmp done;
    
    // popfloat:
    0xDD, 0xD8                      // fstp st
    
    // done:
];

// +10 because we need to add the call and the jump back.
var ourPatch = allocateMemory(thePatch.length + 10);

// Insert our patch at our patch location.
patch(ourPatch, thePatch);

// Insert the address of our float 100.
patchAddress(ourPatch.add(2), float100);

// Insert the original call that we end up replacing with our patch.
insertCall(ourPatch.add(thePatch.length), theCallAddress);

// Insert the jump back to the original code.
insertJmp(ourPatch.add(thePatch.length + 5), theFstp.add(5));


// Nop the instructions at the original code to make room for the jump to our 
// patch.
patch(theFstp, Array(8).fill(0x90));

// Insert the jump to our patch.
insertJmp(theFstp, ourPatch);
