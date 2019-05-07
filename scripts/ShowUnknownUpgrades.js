// Display upgrades that would normally be displayed as '?????????'.

var pattern = scan('3A 85 AB FE FF FF 0F 83');
patch(pattern.add(7), 0x81);
