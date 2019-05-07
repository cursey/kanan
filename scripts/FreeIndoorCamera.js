// Description:
// Allows you to freely rotate the camera while indoors. (created by Step29)

var pattern = scan('57 8B 7D 08 0F 84 ? ? ? ? 8B 8E C8 01 00 00');
patch(pattern.add(4), [0x90, 0xE9]);
