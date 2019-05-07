// Description:
// Speed up dialogues while chatting to NPCs to instant. (created by Step29)

var pattern = scan('76 ? 8B 40 04 89 45 0C');
patch(pattern, 0xEB);
