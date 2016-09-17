// Description:
// Disables chatting notifications from the trade imp while commercing. Will still trigger bandit alert. (created by Step29)

var pattern = scan('8B ?? ?? 03 ?? ?? 3B ?? 08 0F 83');

patch(pattern.add(9), [0x90, 0xE9]);
