// Description: 
// Hide away the graphical icon display of secondary titles worn by players. (created by Step29)

var pattern = scan('C1 E9 14 F6 C1 01 75 ?? 8B');

patch(pattern.add(6), 0xEB);
