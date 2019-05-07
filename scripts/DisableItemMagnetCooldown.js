// Removes the cooldown timer from the Magnet button so item sorting can be done repeatedly.

var pattern = scan('50 52 C7 45 E8 98 3A');
patch(pattern.add(6), [0x00, 0x00]);
