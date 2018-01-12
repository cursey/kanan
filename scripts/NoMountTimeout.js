//Description:
//When you mount a pet, you will not be able to unmount for about 2 seconds.
//Same when you unmount, you won't be able to mount again until 2 seconds later.
//This mod disables that timer and lets you mount/unmount as fast as your internet allows.

//Code and mod found by Licat, their notes and such are below.
//Use CE to search for unknown 4-byte value. This value increases when you mount/dismount,
//and stay unchanged otherwise. You should end up with some 300 values, and 3 of them stand
//out as being much larger (and looks like a timestamp).  By trial and error, freezing
//one of the three values should allow you to skip the timer.

var pattern = scan('89 90 5C 02 00 00');

patch(pattern, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
