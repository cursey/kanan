// Fixes Mana Tunnel Lag By Removing Position Marker (Step29)

var pattern = scan('4D 00 79 00 50 00 6F 00 73 00 69 00 74 00 69 00 6F 00 6E 00 4D 00 61 00 72 00 6B 00 65 00 72 00 49 00 6D 00 61 00 67 00 65 00');

patch(pattern, new Array(42).fill(0));
