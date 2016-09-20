// Originally found in Jinsu Nogi by garang.

// Description:
// Take full control of the interface while in unconcious state (dead!!).

// Walkthrough:
// Finding the address is kind of tricky but:
// CE while alive scan for 4 byte value 0
// CE while dead continue scan for changed values (the value you are looking
// for tends to be small, usually varying between 0 and 2 from what I've seen)
// CE while alive continue scan for values that are 0
// Continue until there are like 20ish results left.
// Start freezing the results at value 1 and while alive, try opening your
// friends list or something.  If the friends list doesn't open then this is the
// address we want. (If you crash while freezing a value at 1, you may want to
// find out what writes to the address first, we are looking for something
// specific).
// Find out whats writes to the address by dieing.
// You should see an inc [edi+910h] or something similar.
// Nop the inc.
//
// Another option to make sure you have the correct address is to see what
// accesses it.  It should be accessed every time you open and close the
// friends list for example.

var theinc = scan('FF 87 ? ? ? ? EB 11');

patch(theinc, Array(6).fill(0x90));
