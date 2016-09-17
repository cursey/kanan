// Description:
// Removes zooming restrictions. Zoom in and zoom out as much as you want.

//Walkthrough: 
// Find value that changes between 400.0,3000.0 as you zoom in and out.
// Find what writes to this value. (fstp [esi+1Ch])
// Change a jp and jnz above it to jmp.

var pattern = scan('7A 05 D9 5D 08 EB 02 DD D8 D9 45 08 D9 45 F8');

patch(pattern, 0xEB); // jp
patch(pattern.add(22), 0xEB); // jnz
