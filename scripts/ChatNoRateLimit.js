// Description:
// Bypass "You cannot enter multiple messages so quickly. Please wait a moment and try again." error message while chatting.

// Walkthrough:
// Easier than ChatAllowSameMsg.
// IDA unicode string view search for:
// code.interface.pli_chathelper.1
// Will be in the same function as the string used for ChatAllowSameMsg.
// Change the jbe that points to the basic block the reference is in to a jmp
var thejbe = scan('76 B0 68 ? ? ? ? 8D 4D DC');

patch(thejbe, 0xEB);
