// Description:
// Automatically skips the "The graphic card installed on your system does not ensure proper execution of the Mabinogi client." when launching the client.

var pattern = scan('83 C4 08 84 C0 75 7F 8D');

patch(pattern.add(5), 0xEB);
