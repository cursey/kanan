var pattern = scan('83 C4 08 84 C0 75 7F 8D');

patch(pattern.add(5), 0xEB);
