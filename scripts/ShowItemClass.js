//Description:
//Toggles on the dev item class ID and attribute flag view.

//Find a check for the devcat title that runs when you mouse over an item.

//Somewhere above that reference is code like this.
//client.exe+1195B4B - B9 61EA0000           - mov ecx,0000EA61 { 60001 }
//client.exe+1195B50 - 66 3B C1              - cmp ax,cx
//client.exe+1195B53 - 0F85 35020000         - jne client.exe+1195D8E
//Edit the jne to not jump.

var pattern = scan('66 3B C1 0F 85 ?? 02 00 00 68 ?? ?? ?? ?? 8D 4D B0');

patch(pattern.add(3), [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
