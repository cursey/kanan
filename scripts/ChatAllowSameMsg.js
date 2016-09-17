// Description: 
// Bypass "Skipped repeated messages for network stability." error message while chatting.

// Walkthrough: 
// Super simple, just open ida unicode string view and search for
// code.interface.window.main_chat.msg_omit_same
// xrefs
// nop the two jnz's that jump to the basic block you find the reference in.
var jnz1 = scan('0F 85 ? ? ? ? 33 FF C6 45 F3 01');
var jnz2 = scan('0F 85 ? ? ? ? 33 FF 80 7D 10 00');

patch(jnz1, Array(6).fill(0x90));
patch(jnz2, Array(6).fill(0x90));
