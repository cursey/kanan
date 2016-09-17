// Description: 
// Increase the font size close to 14px in size. (created by ???)
// Note that it is incompatible with BitmapFont.js, it will break image searching bots, and there's also some text overflow/overlap on some windows to live with.

var pattern = scan('c7 86 a4 00 00 00 0b 00 00 00 c7');

patch(pattern.add(6), 0x0d);
