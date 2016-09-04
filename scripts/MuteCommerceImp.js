// Disables all notifications from the trade imp while commercing. (Created by Step29, converted from mod_sharker by C0ZIEST, fixed by Poshwosh)
var pattern = scan('8B ?? ?? 03 ?? ?? 3B ?? 08 0F 83');
patch(pattern.add(9), [0x90, 0xE9]);
