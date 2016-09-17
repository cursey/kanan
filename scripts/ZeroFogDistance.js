// Description:
// Stops fog from rendering in the distance. Works best when combied with RenderDistance.js. (created by Step29)

var pattern1 = scan('D9 45 14 5D C2 10');
patch(pattern1.add(1), [0xEB, 0x90]);

var pattern2 = scan('D9 45 14 5D C2 10');
patch(pattern2.add(1), [0xEB, 0x90]);
