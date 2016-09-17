// Description: 
// Modify the camera's Field of View. (created by Rydian)

// Configuration: 
// 180 = Mabi's normal value.
// 120 = A common compromise.
// 90 = Quake Pro MLG Airhorn
var desiredFOV = 120;

// Walkthrough:
// Find an fdiv that's reading from a specific address (holding 180).
// Change this instruction to read from an address with our value instead.

// The original code signature.
var thePatchLocation = scan('D9 45 10 D9 56 44 DC 0D ?? ?? ?? 02 DC 35 ?? ?? ?? 02 DC 0D ?? ?? ?? 02');

// The custom value placeholder.
var thePatch = [
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

// Allocate the memory for the custom value.
var ourCodeLocation = allocateMemory(thePatch.length);

// Debug message to show where the custom value is.
dmsg(ourCodeLocation);
// Write the (still placeholder) custom value to the location.
patch(ourCodeLocation, thePatch);

// Replace the placeholder value with the desired value.
patchDouble(ourCodeLocation.add(0), desiredFOV);

// Now overwrite the address in the fdiv of the original code with our address.
patchAddress(thePatchLocation.add(14), ourCodeLocation);
