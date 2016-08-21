// Keeps your personal shop open without a brownie or pet.
// This pattern finds the function that is called when mabi decides you've
// moved too far away from your personal shop and it needs to be closed.
// All we do is make it return immediately so the shop stays open.
var pattern = scan('56 8B F1 E8 ? ? ? ? 84 C0 74 1F');

patch(pattern, [0xC2, 0x04, 0x00]);
