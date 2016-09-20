// Originally found in JinsuNogi.

// Description:
// Adds the option "View Equipment" while mouse right-clicking NPCs. (created by ???)

// References:
// Search1=84 C0 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 6A 2C
// Replace1=38 C0 0F 8B ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 6A 2C
// Value found on r234 NA = >84 C0 0F 85< A7 00 00 00 >8B< CF E8 2A F9 57 FF 84

var pattern = scan('84 C0 0F 85 A7 ?? ?? ?? 8B CF');
patch(pattern.add(0), 0x38);
patch(pattern.add(3), 0x8B);
