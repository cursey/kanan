// Disables screen flashes from occuring. This includes: Shuriken Charge, Focused Fist. (Created by Step29, fixed by Poshwosh)

var pattern = scan('55 1C 53 ?? ?? ?? ?? ?? ?? ?? ?? 56');
patch(pattern.add(2), [0x50]);
