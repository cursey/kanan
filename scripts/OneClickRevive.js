// Description:
// Skips the confirmation when selecting revival option, automatically reviving with just one click as a result. (created by Step29)

var pattern = scan('39 ?? ?? 0F 86 ?? ?? ?? ?? 8B ?? ?? 8B 11');

patch(pattern.add(3), [0x90, 0xE9]);
