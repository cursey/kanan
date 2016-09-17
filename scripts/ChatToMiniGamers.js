// Description:
// Allow you to start a chat with friends who have their status set to "Mini-game".

// Walkthrough:
// From interface.english.txt we find the string to search for by looking for
// 'Your friend is too busy'.
// IDA unicode string view -> code.interface.pli_windowmessengermain.15
// Its referenced twice but we only care about one, the simpler one that also
// has a reference to code.interface.pli_windowmessengermain.1
// Anyway, if you look a few basic blocks above the reference to the string we
// found you'll see a basic block that just pushes an argument onto the stack
// and sets ecx to a global.
// This is the basic block that we want to have called.  You can test and see
// that this block doesnt get executed when you try opening a chat to someone
// whos in Mini-game mode.
// Switch the jnz that jumps to this location to a jmp.

var thejnz = scan('75 13 8D 4D 08 56');

patch(thejnz, 0xEB);
