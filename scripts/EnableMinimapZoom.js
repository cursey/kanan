//Description:
//Allows zooming out on all minimaps instead of just some of them (created by Rydian).

//Walkthrough:
//Current minimap zoom is a 4-byte value for scale.
//So normally it's 1, 2, 4, or 8 depending on zoom.
//It's +70 in the structure, and max zoom is +74.
//Find what writes it, change the write to a high value.

var pattern = scan('89 4E 74 80 78 40 00 74 16');
patch(pattern.add(1), 0x6E);
