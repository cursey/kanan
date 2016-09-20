// Originally found in MAMP by Tyne and IBWK.

// Description:
// Unveil the player character's negative HP instead of just being displayed as DEADLY.

// Walkthrough:
// Easy enough, in IDA unicode string view -> <color=4>DEADLY</color>
// xrefs.
// There should be 3 or so, we will be changing all of them in the same way.
// First change the jnz that jumps to our string reference to a jmp.
// A few basic blocks above that there will be an xor ebx,ebx that we nop.
//
// Changing the jnz to a jmp makes it so mabi displays a number always instead
// of DEADLY.
//
// Nopping the xor ebx,ebx makes it so mabi shows negative health instead of
// clamping it to 0.
//
// Oh, one uses a mov instead of xor, so we nop that mov [ebp-120h], 0
//
// Do that for each reference.

var jnz1 = scan('75 18 68 ? ? ? ? 8D 8D');
var jnz2 = scan('75 07 68 ? ? ? ? EB 1F 6A 0A 68 ? ? ? ? 8D 8D ? ? ? ? 51 53');
var jnz3 = scan('75 07 68 ? ? ? ? EB 1F 6A 0A 68 ? ? ? ? 8D 8D ? ? ? ? 51 50');

patch(jnz1, 0xEB);
patch(jnz2, 0xEB);
patch(jnz3, 0xEB);

var xor1 = scan('33 DB 85 F6 75 1C');
var xor2 = scan('33 DB 85 FF 75 0B');

patch(xor1, [0x90, 0x90]);
patch(xor2, [0x90, 0x90]);

var mov1 = scan('C7 85 ? ? ? ? ? ? ? ? 8B 85 ? ? ? ? 85 F6');

patch(mov1, Array(10).fill(0x90));
