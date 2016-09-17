// Description: 
// Disables white screen flashes from occuring while loading or executing certain skills. (created by Step29)
// For more information refer to https://github.com/cursey/kanan/wiki/List-of-modifications#disablescreenflashjs-created-by-step29

var pattern = scan('55 1C 53 ?? ?? ?? ?? ?? ?? ?? ?? 56');
patch(pattern.add(2), [0x50]);
