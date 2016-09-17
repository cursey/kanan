// Description:
// Disable changing between fullscreen and windowed mode. (created by Rydian)
//
// Walkthrough: 
// There's a byte for if you're in windowed mode (1) or fullscreen (0).
// A lot of adresses behave like this, one example in one run was
// 098B6D6C, careful about messing with addresses too early in memory.
//
// The mov that writes to this can be nop'd to prevent the mode from changing.
// 88 48 3C              - mov [eax+3C],cl
// 8B 56 0C              - mov edx,[esi+0C]
// 83 C2 30              - add edx,30

var pattern = scan('88 48 3C 8B 56 0C 83 C2 30 52');

patch(pattern.add(0), [0x90, 0x90, 0x90]);
