// Allows not just potions to be hotkeyed, but ANY sort of usable item. (Created by ???, fixed by Poshwosh)

// Original mod_sharker script for future reference, I couldn't "pinpoint" this pattern accurately so it will very likely break eventually:
// Item Hotkey [MOD]
// [ItemHotkey]
// Search1=84 C0 74 04 B0 01 EB 02 32 C0 C2 04 00
// Replace1=84 C0 74 04 B0 01 EB 02 B0 01 C2 04 00
// Value found on r234 NA = 02 E8 EC 72 5D FF >84 C0 74< 06 >B0 01< 5D C2 04 00 >32 C0< 5D C2 04 00 CC

var pattern = scan('EC ?? ?? ?? 84 C0 74 ?? B0 01 ?? ?? ?? ?? 32 C0');
patch(pattern.add(14), [0xB0, 0x01]);
