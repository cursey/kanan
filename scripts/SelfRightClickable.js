//
// This script lets you right click yourself.

// IDA unicode string view
// Search for the string: TYPE
// Xrefs
// References twice in one function, thats the one we want.
// This function also references the following strings:
// MECUB
// 10th_anniversary_2014_korea
// ScreenshotReportView
// /eiry/
// /not_attachable/
// Notice that the first argument is stored in edi
// Near the top of the function you will see some compares in the form of
// cmp eax, edi
// Changing the jnz after one of these cmp's to a jmp will enable self-right
// click.

var theJnz = scan('0F 85 ?? ?? ?? ?? 3B D7 0F 85 ?? ?? ?? ?? 8B 8E 90 00 00 00');

patch(theJnz, [0x90, 0xE9]);
