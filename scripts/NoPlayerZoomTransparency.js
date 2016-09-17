// Description:
// Stops players from becoming translucent while colliding the camera with other players. (created by Step29)

var pattern1 = scan('4E F7 DE 1B F6 81 E6 FE 07 00 00');
var pattern2 = scan('74 17 53 57 6a 02 57');

patch(pattern1.add(6), [0xC7, 0xF0, 0x0F]);
patch(pattern2.add(5), 0x05);
