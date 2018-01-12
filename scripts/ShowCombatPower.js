//Description:
//Toggles on the dev CP viewing feature.

//Toggle on, then re-render existing characters if needed.
//Like run away so they vanish then run back.
//Or just go to your HS and back or something.

//Find code that references/pushes the adress containing the following string.
//{0} <mini>CP</mini> {1}
//Somewhere above that reference is code like this.
//B9 61EA0000           - mov ecx,0000EA61 { 60001 }
//66 3B C1              - cmp ax,cx
//0F85 17010000         - jne client.exe+D2F251
//Edit the jne to not jump.

var pattern = scan('0F 85 ? ? ? ? 8B 97 ? ? ? ? 8B 87');

patch(pattern, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);

/*
// This is the original version of this script that is a lot more complicated than
// the new version. It's left here because the information is still good and it is
// still a functional script.

// Originally found in Fantasia.

// Description:
// Display Combat Power (CP) information when holding down ALT in numerical value as opposed to just ranking. (example: weakest White Spider > 50 weakest White Spider)

// Walkthrough:
// IDA unicode string view -> <mini>WEAKEST </mini> (there are others for
// strong, awful, etc)
// check the xrefs (should only be one)
// These are the strings we replace and this is the function we intercept.
// 
// The basic idea is to fix the checks this funciton does so that it runs its 
// switch statement on other players, then patch the switch statement so that
// it only uses the string our hook generates for each player. We end up using
// the same functions this function uses to determine the combat power
// difference, and end up reimplementing the switch statement ourselves in a
// way.


// 
// Functions we need to call (that are called by the function we found).
//
var calcCombatPowerDifferencePtr = scan('55 8B EC 83 EC 08 56 8B F1 8B 06 8B 50 58 FF D2 8B C8 E8 ? ? ? ? D8 1D');
var calcCombatPowerDifference = new NativeFunction(calcCombatPowerDifferencePtr, 'int', ['pointer', 'int'], 'thiscall');

var getUnkObjectCall = scan('E8 ? ? ? ? 8B F8 3B FB 0F 84 ? ? ? ? 8B CE E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 8B CE');
var getUnkObjectPtr = calcAbsAddress(getUnkObjectCall);
var getUnkObject = new NativeFunction(getUnkObjectPtr, 'pointer', ['pointer'], 'thiscall');

//
// Checks we need to fix.
//
var isPlayerCheck1 = scan('0F 85 ? ? ? ? 56 8B CF E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 8B CE E8 ? ? ? ? C1 EA 10'); // This is from the function that calls the one we found.
var isPlayerCheck2 = scan('0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B 06'); // This is in the function we found near the top.
var isLocalPlayerCheck = scan('0F 85 ?? ?? ?? ?? 89 5D F0 C7 45 ?? ?? ?? ?? ?? 89 5D E8'); // this is in the function we found right before the switch.

// 
// This is the main switch statement in the function we found.
//
// It looks like this:
// cmp eax, 5
// ja <addr>
// jmp off_<addr>[eax * 4]
//
var theSwitch = scan(' 83 F8 05 77 30');

//
// Make room for our replacement string.
//
var strMem = allocateMemory(1000);

// 
// Apply all our patches.
///

// The checks.
patch(isPlayerCheck1, [0x90, 0xE9]);
patch(isPlayerCheck2, Array(6).fill(0x90));
patch(isLocalPlayerCheck, Array(6).fill(0x90));

// Patches the common cmp, ja and jmp instructions used by switch statements.
patch(theSwitch, Array(12).fill(0x90));

// Overwrite the location of the default string (just the <mini>WEAKEST </mini> one) with our new string.
patchPointer(theSwitch.add(12 + 1), strMem);

// 
// Hook the function we found.
//
var createAltNameStr = scan('55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC 18 53 56 57 A1 ?? ?? ?? ?? 33 C5 50 8D 45 F4 64 A3 ?? ?? ?? ?? 8B F1 33 DB 89 5D E0');

Interceptor.attach(createAltNameStr, {
    onEnter(args) {
        var getUnkObjectThisPtr = Memory.readPointer(getUnkObjectCall.sub(4));

        if (getUnkObjectThisPtr.isNull()) {
            return;
        }

        var getUnkObjectThis = Memory.readPointer(getUnkObjectThisPtr);

        if (getUnkObjectThis.isNull()) {
            return;
        }

        var v3 = getUnkObject(getUnkObjectThis);

        if (v3.isNull()) {
            return;
        }
        
        // Follow through the execution of the function to find these offsets,
        // they are pretty easy to get.
        var thisPtr = this.context.ecx;
        var entPtr = Memory.readPointer(thisPtr.add(0x90));
        var cp = Memory.readFloat(entPtr.add(0x11c));

        var cpStr = cp.toFixed();

        switch (calcCombatPowerDifference(v3, thisPtr.toInt32()))
        {
        case 1: cpStr += " <mini>WEAKEST </mini>"; break;
        case 2: cpStr += " <mini>WEAK </mini>"; break;
        case 4: cpStr += " <mini>STRONG </mini>"; break;
        case 5: cpStr += " <mini>AWFUL </mini>"; break;
        case 6: cpStr += " <mini>BOSS </mini>"; break;
        default: cpStr += " <mini>SIMILAR </mini>";
        }

        Memory.writeUtf16String(strMem, cpStr);
    }
});
*/