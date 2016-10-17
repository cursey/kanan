// This script lets you stay in lance counter longer before it automatically
// cancels.

// NOTE: Only use this script if you are also using CancelableLanceCounter.js
// NOTE: If you do use this without CancelableLanceCounter.js make sure to keep
// the desired time very reasoanble otherwise you can put the skill into
// cooldown for a *VERY* long time.

// Stumbled upon this by reversing things around the function that is patched
// by CancelableLanceCounter.js
// Find the other function that references the string LIMIT_T and also LS_LUT.
// A call or two above the first reference to LIMIT_T will be a small function
// that gets called whenever you load lance counter and it also returns the
// constant 0x3A98 in one of its branches (that isn't taken by default). After
// forcing it to take that branch (by changing the jump) notice that lance
// counter now lasts 0x3A98 milliseconds (15000 or 15 seconds).
// Make this function return our desired time.

// In milliseconds (1 minute by default).
var desiredLanceCounterTime = getConfigValue('lance_counter_time', 60000);

// The signature for the function ended up being really long (because there are
// similar functions for other skills most likely) so we take the pattern from
// where it was called in the function that referenced the LIMIT_T and LS_LUT
// strings.
var theCall = scan('E8 ? ? ? ? 8B 13 50 8B 42 68');
var theOffset = Memory.readS32(theCall.add(1));
var theAddress = theCall.add(5).toInt32() + theOffset;

// patch expects a NativePointer so use the ptr function to conver theAddress
// from a javascript Number to a NativePointer.
patch(ptr(theAddress), [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00, 0x90, 0x90]);
patchDword(ptr(theAddress).add(1), desiredLanceCounterTime);

