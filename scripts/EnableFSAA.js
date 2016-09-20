// Originally found in Fantasia.

// Description:
// Enables the option to turn on Full-screen Anti-aliasing in Mabinogi's Options menu.

// Walkthrough:
// IDA unicode string view -> code.interface.window.option.fsaa_text.
// xrefs should show 2 references in the same function.
// The call above the first reference should be a function called approx. 2033 
// times and refrence strings like CView, CButton, CToggleButton, CRadioButton,
// etc. Make note that this function most likely creates a UI widget.
// Scroll down in the function that referenced our original string and see 
// references to code.interface.window.option.fsaa_none and 
// code.option.interface.window.option.tooltip.fsaa_text. 
// Further down you'll spot another call to that function that creates a UI 
// widget, and a reference to code.interface.window.option.skin_color_text.
// This is the creation of the next widget. 
// After fidgiting around it turns out the call right above the creation of the
// next widget sets the fsaa control to disabled. 
//
// The call looks like:
// push ebx
// call edx
//
// ebx is 0 for the entirity of the function.
// I put a bp on call ebx to see what its calling.
// Its calling a function that sets weather each ui widget is enabled/disabled.
// If there was room to push 1 instead of push ebx we could do that to keep the
// fsaa combo box enabled, but we don't have 2 bytes to work with.
// Turns out controls are enabled by default, so we can just nop the push and 
// call.
var thepush = scan('53 FF D2 8B 0D ? ? ? ? 6A 0C E8 ? ? ? ? 68 ? ? ? ? 89 45 D0');

patch(thepush, [0x90, 0x90, 0x90]);
