// IDA unicode string view -> code.interface.msg.etc.no_channelmove_npctalk
// xrefs
// Should be in a switch statement where you can see other denail strings being
// referenced.
// Skip over the siwtch statement.
var switchBoundsJa = scan('0F 87 ?? ?? ?? ?? FF 24 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D E8 E8 ?? ?? ?? ?? C6 45 FC 01 8D 4D E8');

patch(switchBoundsJa, [0x90, 0xE9]);
