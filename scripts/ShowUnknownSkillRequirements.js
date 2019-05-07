// Display skill requirements that would normally be displayed as '?????????'.

var pattern = scan('84 C0 74 7D 57');
patch(pattern.add(2), [0x90, 0x90]);
