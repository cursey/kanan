// Native methods used by this script.
var SetWindowPos = new NativeFunction(getProcAddress('User32.dll', 'SetWindowPos'),
        'int', ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'uint'], 'stdcall');
var GetWindowLongA = new NativeFunction(getProcAddress('User32.dll', 'GetWindowLongA'),
        'long', ['pointer', 'int'], 'stdcall');
var SetWindowLongA = new NativeFunction(getProcAddress('User32.dll', 'SetWindowLongA'),
        'long', ['pointer', 'int', 'long'], 'stdcall');
var FindWindowA = new NativeFunction(getProcAddress('User32.dll', 'FindWindowA'),
        'pointer', ['pointer', 'pointer'], 'stdcall');
var GetSystemMetrics = new NativeFunction(getProcAddress('User32.dll', 'GetSystemMetrics'),
        'int', ['int'], 'stdcall');

// Constants used by the native methods.
var SM_CXSCREEN = 0;
var SM_CYSCREEN = 1;
var GWL_STYLE = -16;
var WS_BORDER = 0x00800000;
var WS_CAPTION = 0x00C00000;
var WS_THICKFRAME = 0x00040000;
var HWND_TOP = ptr(0);
var SWP_FRAMECHANGED = 0x0020;

// Get the screen size.
var width = GetSystemMetrics(SM_CXSCREEN);
var height = GetSystemMetrics(SM_CYSCREEN);

if (debug) {
    send("Screen width: " + width);
    send("Screen height: " + height);
}

// Get the mabi window.
var mabiStr = allocateStr('Mabinogi');
var mabiWnd = FindWindowA(mabiStr, mabiStr);

freeStr(mabiStr);

if (debug) {
    send("Mabinogi window: " + mabiWnd);
}

if (mabiWnd.isNull()) {
    send("Failed to find mabi window.");
}

// Remove the mabi window styling and fullscreen the window size.
var oldStyle = 0;

while (oldStyle == 0) {
    SetWindowPos(mabiWnd, HWND_TOP, 0, 0, width, height, SWP_FRAMECHANGED);

    var wndStyle = GetWindowLongA(mabiWnd, GWL_STYLE) & ~(WS_BORDER | WS_CAPTION | WS_THICKFRAME);

    oldStyle = SetWindowLongA(mabiWnd, GWL_STYLE, wndStyle);
}


