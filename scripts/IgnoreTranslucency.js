// Description:
// Stops objects from becoming translucent while colliding the camera with other objects. (created by Rydian)

var pattern = scan('39 70 04 75 39 3B FE');

patch(pattern.add(3), [0x90, 0x90]);
