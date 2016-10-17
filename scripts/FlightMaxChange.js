//Description:
//Change the maximum flight height cap, allowing you to go much higher or stay low (created by Rydian).

//Configuration:
//50000 = I can see my house from here!
//10000 = Mabi's normal limit.
//2000 = Low safe value, also grants instant takeoff.
var desiredHeightCap = getConfigValue('height_cap', 2000);

//Walkthrough:
//Find a float of 10000 in early static memory that's read when flying upwards.
//10000 was determined by finding the flight height normally and estimating the cap.

//The original code signature.
var thePatchLocation = scan('D9 05 ?? ?? ?? ?? 5D C2 04 00 8B 41 10');

//Allocate the memory for the custom value.
var ourFloat = allocateMemory(4);
//Debug message to show where the custom value is.
dmsg(ourFloat);

//Write the custom value to the location.
patchFloat(ourFloat, desiredHeightCap);

//Replace the address in the target code with the new address.
patchAddress(thePatchLocation.add(2), ourFloat);
