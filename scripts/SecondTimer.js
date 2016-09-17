// Description:
// Update the time elapsed timer in theatre/shadow missions every 1 second as opposed to every 15 seconds.

// Walkthrough: 
// Read over MinuteClock.js for the bit about magic number division.
// String of interest is 'Elapsed Time'
// IDA unicode string view -> code.interface.pli_windowtaskbar.31
// xrefs
// Twice in the same function.
// Locate the magic number division (15 corrisponds to 88888889h).
// Nop the entire magic number division.
// Notice that the clock still seems to update every 15 seconds, but shows the
// actual second timer at this point.
// Scroll near the top of the function and notice a cmp eax, 0Fh
// Change to cmp eax, 1h and notice it updates every two seconds, change it to
// cmp eax, 0h and now it updates the Elapsed Time every second.
// Next string is also located in this function 'Time Left'
// code.interface.pli_windowtaskbar.23
// Division seems to be handed off to a clamping function that divides safely
// or something for the Time Left number.
// Notice a push 0Fh as an argument to this safe division function
// Change to push 01h and now time left is counting down seconds but is not
// formatted correctly.
// Result is stored in esi, remove the 'correction' applied after the division
// (a shl and sub).
// Now both the Elapsed Time and Time Left are displying seconds and updated
// every second.
var magicnumdiv = scan('B8 ? ? ? ? F7 E6 C1 EA 03 42');
var cmpto15 = scan('83 F8 0F 0F 97 C0');
var push15 = scan('6A 0F 83 DE 00');
var shl4 = scan('C1 E6 04 68 ? ? ? ? 8D 4D EC');

patch(magicnumdiv, Array(18).fill(0x90)); // Removes the division by 15 showing each second.
patch(cmpto15.add(2), 0x00); // Causes it to update the time every second.
patch(push15.add(1), 0x01); // Causes it to devide the countdown timer by 1 instead of 15.
patch(shl4, [0x90, 0x90, 0x90]); // Remove the shl by 4 which is part of fixing the second timer after the division.
patch(shl4.add(11), [0x90, 0x90]); // Removes the sub which is part of fixing the second timer after the division.
