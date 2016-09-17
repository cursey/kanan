// Description:
// While in windowed mode, stretch Mabinogi's window till the edges of the screen just until the taskbar and remove all borders around it.

// Native methods used by this script.
var SetWindowPos = native('User32.dll', 'SetWindowPos', 'int', ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'uint'], 'stdcall');
var GetWindowLongA = native('User32.dll', 'GetWindowLongA', 'long', ['pointer', 'int'], 'stdcall');
var SetWindowLongA = native('User32.dll', 'SetWindowLongA', 'long', ['pointer', 'int', 'long'], 'stdcall');
var FindWindowA = native('User32.dll', 'FindWindowA', 'pointer', ['pointer', 'pointer'], 'stdcall');
var SystemParametersInfoA = native('User32.dll', 'SystemParametersInfoA', 'int', ['uint', 'uint', 'pointer', 'uint'], 'stdcall');

// Constants used by the native methods.
var GWL_STYLE = -16;
var WS_BORDER = 0x00800000;
var WS_CAPTION = 0x00C00000;
var WS_THICKFRAME = 0x00040000;
var HWND_TOP = ptr(0);
var SWP_FRAMECHANGED = 0x0020;
var SPI_GETWORKAREA = 0x0030;

// Get the work area (thanks Warsen).
var rect = allocateMemory(16);

SystemParametersInfoA(SPI_GETWORKAREA, 0, rect, 0);

var x = Memory.readInt(rect);
var y = Memory.readInt(rect.add(4));
var width = Memory.readInt(rect.add(8)) - x;
var height = Memory.readInt(rect.add(12)) - y;

freeMemory(rect, 16);

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
    if (SetWindowPos(mabiWnd, HWND_TOP, x, y, width, height, SWP_FRAMECHANGED) == 0) {
        continue;
    }

    var wndStyle = GetWindowLongA(mabiWnd, GWL_STYLE) & ~(WS_BORDER | WS_CAPTION | WS_THICKFRAME);

    oldStyle = SetWindowLongA(mabiWnd, GWL_STYLE, wndStyle);
}
