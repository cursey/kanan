// Originally found in Fantasia.

// Description: 
// Bypasses the "Currently logged channel." error message and allows you to move to the same channel.

// Walkthrough:
// In IDA string view -> unicode strings
// Search for 'code.interface.msg.channel_move.current'.
// Look @ the xrefs.

var pattern = scan('0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D E0 E8 ?? ?? ?? ?? C6 45 FC 04 8D 55 E0 52 8D 45 B8');

patch(pattern, [0x90, 0xE9]);
