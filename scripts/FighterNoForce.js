// Description: 
// While in hide interface mode, using chain combo fighter skills will turn the interface back on. This disables this trigger, persisting the interface to stay hidden. (created by Rydian)

var secondchain = scan('83 79 44 01 75 09 6A 00 6A 00 E8');
patch(secondchain.add(4), 0xEB);
var thirdchain = scan('83 79 44 01 75 09 6A 00 6A 00 E8');
patch(thirdchain.add(4), 0xEB);
