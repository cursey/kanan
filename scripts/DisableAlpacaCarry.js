// Change mounting logic to always ride an Alpaca and never carry it. Credits: Rydian

var pattern = scan('83 F8 19 72 0F 8B CE');
patch(pattern.add(3), [0x90, 0x90]);
