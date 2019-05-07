// Display quest objectives that would normally be displayed as '?????????'

var pattern = scan('38 5E 0D 75 17');
patch(pattern.add(3), [0xEB]);
