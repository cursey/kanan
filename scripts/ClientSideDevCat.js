// Description:
// Enables client-sided effects provided with the devCAT title including visible HP values under HP bars. (created by Rydian)
// For more information refer to https://github.com/cursey/kanan/wiki/List-of-modifications#clientsidedevcatjs-created-by-rydian

// Walkthrough:
//Title IDs are in data/db/title.xml.
//Find yours, find the code that reads it.
//Right after it returns, there's a check to modify.

var pattern = scan('74 21 8B 16 8B 82 94 00 00 00 8B CE');
patch(pattern.add(0), 0xEB);
