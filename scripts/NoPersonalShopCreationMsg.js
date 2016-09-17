// Description:
// Automatically confirms the "A shop has been created. ... Beware that if you are more than 5 yards away, the shop will close." warning message when creating a personal shop.

// Walkthrough:
// IDA unicode string view -> code.client.msg.ps_shop.opened2
// xrefs
// Scroll down just a bit in graph view and you'll see a function being called
// with three 1's pushed as parameters.  We nop all the pushes and the function
// that is called to remove the message box from being created.
var pattern = scan('6A 01 53 53 6A 01 53 6A 01 53 53 8D 55 E8 52 E8 ? ? ? ? C6 45 FC 04');

patch(pattern, Array(20).fill(0x90));
