// Adds the option "View Equipment" when right-clicking NPCs. (Created by ???, fixed by Poshwosh)

// Original mod_sharker script for future reference, I couldn't "pinpoint" this pattern accurately so it will very likely break eventually:
// //View NPC Equipment [MOD]
// [ViewNPCEquip]
// Search1=84 C0 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 6A 2C
// Replace1=38 C0 0F 8B ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 6A 2C
// Value found on r234 NA = >84 C0 0F 85< A7 00 00 00 >8B< CF E8 2A F9 57 FF 84

var pattern = scan('84 C0 0F 85 A7 ?? ?? ?? 8B CF');
patch(pattern.add(0), 0x38);
patch(pattern.add(3), 0x8B);
