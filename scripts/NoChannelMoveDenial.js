// Originally found in JinsuNogi.

// Description:
// Automatically confirms the "You cannot switch to another channel while in conversation with an NPC." error message when attempting to change channels in NPC conversation.

// Walkthrough:
// IDA unicode string view -> code.interface.msg.etc.no_channelmove_npctalk
// xrefs
// Should be in a switch statement where you can see other denail strings being
// referenced.
// Change the first jz in this function to skip all the checks.

var firstJz = scan('0F 84 ?? ?? ?? ?? 89 5D F0 89 5D FC 8B 8E');

patch(firstJz, [0x90, 0xE9]);
