// Description: 
// Load other utilities of the .DLL extension onto the Mabinogi client.

// Configuration:
// Add the path of any dlls you want to load to this array.  The path is relative to the directory kanan.py is located.
// For example, if you create a folder called 'dlls' in the directory kanan.py is located and in that folder you have 'mod1.dll' and 'mod2.dll' your array would look like this:
// var dlls = ["dlls\\mod1.dll", "dlls\\mod2.dll"];
// Note that backslashes have to be doubled cause of javascript.
var dlls = [];

for (var i = 0; i < dlls.length; ++i) {
    var dllPath = path + "\\" + dlls[i];

    dmsg("Attempting to load: " + dllPath);

    if (loadDll(dllPath).isNull()) {
        msg("Failed to load: " + dllPath);
    }
    else {
        msg("Loaded: " + dllPath);
    }
}


