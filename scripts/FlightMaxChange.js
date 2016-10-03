//Description: 
//Change the maximum flight height cap, allowing you to go much higher or stay low (created by Rydian).

//Configuration: 
//50000 = I can see my house from here!
//10000 = Mabi's normal limit.
//2000 = Low safe value, also grants instant takeoff.
var desiredHeightCap = 2000;

//Walkthrough:
//Find a float of 10000 in early static memory that's read when flying upwards.
//10000 was determined by finding the flight height normally and estimating the cap.

//The original code signature.
var thePatchLocation = scan('D9 05 04 4A 8A 02 5D C2 04 00 8B 41 10');

//The custom value placeholder.
var thePatch = [
	0xFF, 0xFF, 0xFF, 0xFF
];

//Allocate the memory for the custom value.
var ourCodeLocation = allocateMemory(thePatch.length);

//Debug message to show where the custom value is.
dmsg(ourCodeLocation);
//Write the (still placeholder) custom value to the location.
patch(ourCodeLocation, thePatch);

//Replace the placeholder value with the desired value.
patchFloat(ourCodeLocation.add(0), desiredHeightCap);

//Now overwrite the address in the fdiv of the original code with our address.
patchAddress(thePatchLocation.add(2), ourCodeLocation);
