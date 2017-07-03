//Description:
//Toggles on the dev CP viewing feature.

//Toggle on, then re-render existing characters if needed.
//Like run away so they vanish then run back.
//Or just go to your HS and back or something.

//Find code that references/pushes the adress containing the following string.
//{0} <mini>CP</mini> {1}
//Somewhere above that reference is code like this.
//B9 61EA0000           - mov ecx,0000EA61 { 60001 }
//66 3B C1              - cmp ax,cx
//0F85 17010000         - jne client.exe+D2F251
//Edit the jne to not jump.

var pattern = scan('0F 85 ? ? ? ? 8B 97 ? ? ? ? 8B 87');

patch(pattern, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
