// Description:
// Automatically enable Transformation Mastery's Collect Mode and persist it through channel change and log out. (created by Rydian)

var pattern = scan('38 5F 78 0F 84 C9 02 00 00 8B CE');

patch(pattern.add(4), 0x85);
