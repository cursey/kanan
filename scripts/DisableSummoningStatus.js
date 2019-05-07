// Removes the temporary 'Summoning...' popup while summoning a pet.

var pattern = scan('8D 4D EC 38 5D 08 74 5A');
patch(pattern.add(-19), [0x90, 0xE9]);
