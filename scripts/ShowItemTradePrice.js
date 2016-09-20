// Originally found in JinsuNogi.

// Description:
// Always show purchase and resale value of items when viewing tooltips, not just in trade window.

// Walkthrough:
// This one's really simple.  Turns out theres two obvious strings for us to
// find!  Finding out what the strings were was easy enough.  Just open up
// interface.english.txt and search for 'Shop Purchase Price:'.  This tells
// you the name of the string we want to search in IDA for:
//
// 'window.pocket.tooltip.trade_pur_price'
//
// Of course you wont find that string in IDA without adding 'code.interface'
// to it.  So the UNICODE string we search for is:
//
// 'code.interface.window.pocket.tooltip.trade_pur_price'
//
// Xrefs should show only a single reference, and further down in graph view
// you should see:
//
// 'code.interface.window.pocket.tooltip.trade_sell_price'
//
// referenced as well.  Simply nop the jnz before the basic block you find the
// first string in.

var pattern = scan('0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D F0 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D D8');

patch(pattern, Array(6).fill(0x90));
