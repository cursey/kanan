// Originally found in Gerent/GerentxNogi by Joe.

// Description:
// Automatically confirms the "Moving to another channel incurs same penalties as re-login." warning message when opening the move channel window.

// Walkthrough: 
// IDA unicode string view -> code.interface.msg.channel_move.desc
// xrefs
// Scroll down till you find a basic block that pushes the value 1 three times
// and makes one call.  The function that is called should reference the string
// 'CMessageView' in it.
// This is the call that creates the description message box.

var firstPush = scan('6A 01 53 53 6A 01 53 6A 01 56 8D 4D DC');

patch(firstPush, Array(29).fill(0x90)); // Nop all the pushes and the call.
