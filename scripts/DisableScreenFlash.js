// Disables white screen flashes from occuring while loading or executing the following skills: Shuriken Charge, Focused Fist, Meteor Strike, Thunder, and Critical Hit. (Created by Step29, fixed by Poshwosh)

var pattern = scan('55 1C 53 ?? ?? ?? ?? ?? ?? ?? ?? 56');
patch(pattern.add(2), [0x50]);
