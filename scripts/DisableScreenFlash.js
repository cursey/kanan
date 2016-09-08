// Disables screen flashes from occuring. This includes: Shuriken Charge, Focused Fist. (Created by Step29, fixed by Poshwosh)

var pattern = scan('55 1C 53 ?? ?? ?? ?? ?? ?? ?? ?? 56');
patch(pattern.add(0), [0x6A, 0x00, 0x90]);
