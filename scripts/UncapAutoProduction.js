// Removes the default cap when producing items through automatic production with the skills Refining, Weaving, Potion Making, Handicraft, Carpentry, Engineering and Magic Craft. (Created by Step29, converted by C0ZIEST)

var pattern1 = scan('66 39 86 ?? ?? ?? ?? 76 07 66');
patch(pattern1.add(7), 0xEB);
var pattern2 = scan('66 39 86 ?? ?? ?? ?? 76 07 66');
patch(pattern2.add(7), 0xEB);
