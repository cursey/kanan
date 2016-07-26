// Objects Between Camera and Character Do Not Become Translucent (Rydian)

var pattern = scan('39 70 04 75 39 3B FE');

patch(pattern.add(3), [0x90, 0x90]);
