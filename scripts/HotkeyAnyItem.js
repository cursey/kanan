// Allows not just potions to be hotkeyed, but ANY sort of usable item. (Created by ???, fixed by Poshwosh)

// Original mod_sharker script for future reference (this mod is hard to "pinpoint" and has been changed throughout the years so it will very likely break eventually again):
// Item Hotkey [MOD]
// [ItemHotkey]
// Search1=84 C0 74 04 B0 01 EB 02 32 C0 C2 04 00
// Replace1=84 C0 74 04 B0 01 EB 02 B0 01 C2 04 00
// Value found on r235 NA = >84 C0 74< 06 >B0 01< 5D C2 04 00 >32 C0< 5D C2 04 00 CC
// There are multiple results, luckily the first result is the right one.

var pattern = scan('84 C0 74 06 B0 01 5D C2 04 00 32 C0 5D C2 04 00 CC');
patch(pattern.add(10), [0xB0, 0x01]);
