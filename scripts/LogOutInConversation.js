// Originally found in JinsuNogi.

// Description:
// Automatically confirms the "You cannot log off while in conversation with an NPC." error message while attempting to log off in NPC conversation. (created by Rydian)

// Walkthrough:
// 83 78 4C 00           - cmp dword ptr [eax+4C],00
// 74 21                 - je Client.exe+150280C
// That line of code reads the "talking to NPCs" flag (4byte, 0 or 1).
// After the function it's in returns, there's a test and a je.
// Change the je to a jmp to change the logic so you can always log.

// The pattern matches two code samples, right now we want the first.
var pattern = scan('84 C0 74 19 B8 ?? ?? ?? ?? 8B 4D F4 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B E5 5D C2 04 00');

patch(pattern.add(2), 0xEB);
