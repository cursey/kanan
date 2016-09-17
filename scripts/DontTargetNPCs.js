// Description:
// Disable targeting NPCs while holding down CTRL.

// Walkthrough: 
// Don't target NPCs when holding ctrl.
// In IDA string view -> unicode strings
// Search for 'enemy > npc'.
// Change push to push 'enemy' (we reuse the enemy str found nearby).

var pattern = scan('68 ?? ?? ?? ?? EB 05 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 86');

copy(pattern.add(1), pattern.add(8), 4);
