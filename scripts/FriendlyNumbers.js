// This script inserts commas in long numbers such as the price of items.

// These are the steps I follows to create this script:
// Have Rydian send you a picture of where the price of an item is being read
// from memory. 
//
// Or find the function that references the string:
// code.interface.window.buy.price_text
// which will have the instruction that reads the number close by.
//
// Reverse the functions that are called after the price has been read from
// memory.
// Notice that one of the functions references the string `%s`.
// This is the 'format string' string which means the number is being converted
// to a string prior to that function being called.
// Look above to see the function called immediately after reading the price 
// and notice that its return value is being fed into the format string 
// function we found.
// That function is the one that converts an integer to a string.
// Reverse that function and find a call to a function that calls itow_s 
// multipul times. 
// itow_s converts an integer to a wide string.
// Notice that the actual itow_s calls don't seem to be called all that
// regularly though.
// Notice that the function also references the string `%d`. 
// This is the 'format decimal' string, which means this could also be 
// converting our number.
// Notice that this part of the function is called as expected.
// Intercept the function and fix the number on return.

var intToStringFunction = scan('55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC 28 A1 ? ? ? ? 33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 ? ? ? ? 33 C0');

Interceptor.attach(intToStringFunction, {
    onLeave(retval) {
        // Destructure the mabi str.
        var mabiStr = Memory.readPointer(retval);
        var strPtr = mabiStr.add(0x1C);
        var lenPtr = mabiStr.add(0xC)

        // Read the current string (the number value without commas).
        var str = Memory.readUtf16String(strPtr);

        // Add commas to it.
        str = str.replace(/\B(?=(\d{3})+(?!\d))/g, ',');

        dmsg(str);

        // Write the new string to the mabi str and update the length of the
        // mabistr.
        Memory.writeUtf16String(strPtr, str);
        Memory.writeU32(lenPtr, str.length);
    }
});