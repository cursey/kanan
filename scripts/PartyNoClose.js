//make party always up until you close it 
//like abyss "Party Time" (creator ???)

var PtNoClose = scan('55 8B EC 56 8B F1 8B 46 64 83 78 08 00 74 32');

patch(PtNoClose.add(13), 0xEB);
