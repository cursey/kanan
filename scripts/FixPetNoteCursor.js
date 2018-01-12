// Description:
// Causes the cursor to jump to the end when editing a pet note, allowing you to erase what was previously written.

//Find the 4-byte value that determines where the cursor is
//when editing or writing a pet note.  Far left is 0, each
//character past that is plus 1.

//Find the code that writes to this address when you're
//typing, incrementing the value.

//Change the inc to instead add an extremely high value (EBP)
//to make sure the cursor jumps to the end of the note.
//inc [esi+0000010C]
//to
//add [esi+0000010C],ebp

var pattern = scan('C7 45 08 00 00 00 00 FF 86 10 01 00 00');

patch(pattern.add(7), [0x01, 0xAE]);
