// Disables the restriction of resizing the minimap while in dungeons. (Created by Step29, fixed by Poshwosh)

var pattern1 = scan('C2 8D ?? ?? ?? ?? ?? ?? B8 B4 00 00 00');
patch(pattern1.add(9), 0xFF);
var pattern2 = scan('BF B4 00 00 00 6A');
patch(pattern2.add(1), 0x19);
