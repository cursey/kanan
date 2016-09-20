// Originally found in Fantasia.

// Description:
// Changes the text color of entities while holding down ALT to white (#FFFFFF).

// Walkthrough:
// Find the function that generates the alt text (see ShowCombatPower.js).
// The function that calls that text generating function also sets the the color
// that the text will be, so xrefs to find the calling function.
// Near the top you'll see some hex values being moved into a structure, they
// look like FF99CC00h 3099CC00h FF3366FFh etc.
// The one we want is the last one, FF3366FFh, to make it white just set it to
// FFFFFFFFh. That will make everyone elses alt text white. To make our own alt
// text white, change FF99CC00h if you want (by default we keep it as it is).
//
// I think the first part of the color code is alpha.

var movColor = scan('C7 46 ? ? ? ? ? C7 46 ? ? ? ? ? 68');

patch(movColor.add(3), [0xFF, 0xFF, 0xFF, 0xFF]);
