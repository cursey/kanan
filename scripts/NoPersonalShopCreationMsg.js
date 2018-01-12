// Description:
// Automatically confirms the "A shop has been created. ... Beware that if you are more than 5 yards away, the shop will close." warning message when creating a personal shop.

// Walkthrough:
// IDA unicode string view -> code.client.msg.ps_shop.opened2
// xrefs
// Scroll down just a bit in graph view and you'll see a function being called
// with three 1's pushed as parameters.  We nop all the pushes and the function
// that is called to remove the message box from being created.
var pattern = scan('52 53 6A ?? 53 53 6A ?? 53 6A ?? 53 53 8D 45 E4 50 E8 ?? ?? ?? ?? C6 45 FC ?? 8B 4D EC 3B CB 74 ?? E8 ?? ?? ?? ?? 89 5D EC C6 45 FC ?? 8B 4D E4 3B CB 74 ?? E8 ?? ?? ?? ?? 89 5D E4 C6 45 FC ??');

patch(pattern, Array(22).fill(0x90));
