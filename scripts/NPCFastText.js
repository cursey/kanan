// Description:
// Speed up dialogues while chatting to NPCs to instant. (created by Step29)

var pattern = scan('8B 08 33 FF 3B CF 76 2A');

patch(pattern.add(6), 0xEB);
