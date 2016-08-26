// Larger TrueType Font size. Not compatible with bitmap font, if enabled.
// Notes:
//  - If you're using bots that search text images, this will break them.
//  - Dev: Cannot increase font size any higher without causing crashes.
//  - There's also some text overflow/overlap on some windows to live with.

var pattern = scan('c7 86 a4 00 00 00 0b 00 00 00 c7');

patch(pattern.add(6), 0x0d);
