// Description:
// Enables the maximize window button and starts the client maximized.
// Only good if BorderlessWindowedMode.js is disabled.

// Native methods used by this script.
var GetWindowLongA = native('User32.dll', 'GetWindowLongA', 'long', ['pointer', 'int'], 'stdcall');
var SetWindowLongA = native('User32.dll', 'SetWindowLongA', 'long', ['pointer', 'int', 'long'], 'stdcall');
var FindWindowA = native('User32.dll', 'FindWindowA', 'pointer', ['pointer', 'pointer'], 'stdcall');
var ShowWindow = native('User32.dll', 'ShowWindow', 'bool', ['pointer', 'int'], 'stdcall');

// Constants used by the native methods.
var GWL_STYLE = -16;
var WS_MAXIMIZEBOX = 0x00010000;
var SW_MAXIMIZE = 3;

// Get the mabi window.
var mabiStr = allocateStr('Mabinogi');
var mabiWnd = FindWindowA(mabiStr, mabiStr);

freeStr(mabiStr);

if (debug) {
    msg("Mabinogi window: " + mabiWnd);
}

if (mabiWnd.isNull()) {
    msg("Failed to find mabi window.");
}

// Remove the mabi window styling and fullscreen the window size.
var oldStyle = 0;

while (oldStyle == 0) {
    var wndStyle = GetWindowLongA(mabiWnd, GWL_STYLE) | WS_MAXIMIZEBOX;

    oldStyle = SetWindowLongA(mabiWnd, GWL_STYLE, wndStyle);

    ShowWindow(mabiWnd, SW_MAXIMIZE);
}
