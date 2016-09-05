// Native functions used by this script.
var setsockopt = new NativeFunction(getProcAddress('Ws2_32.dll', 'setsockopt'),
    'int', ['uint', 'int', 'int', 'pointer', 'int'], 'stdcall');
var WSAGetLastError = new NativeFunction(getProcAddress('Ws2_32.dll', 'WSAGetLastError'),
    'int', [], 'stdcall');

// Constants used by this script.
var IPPROTO_TCP = 6;
var TCP_NODELAY = 0x0001;

// Calls socket().
var createSocketPtr = scan('55 8B EC 83 EC 08 56 57 8B 7D 0C 8B CF');

Interceptor.attach(createSocketPtr, {
    onEnter(args) {
        // args[1] is where the function stores the SOCKET.
        this.socket = args[1];
    },
    onLeave(retval) {
        var socket = Memory.readU32(this.socket); 
        var nodelay = allocateMemory(4);

        Memory.writeU32(nodelay, 1);

        dmsg("Socket: " + socket);
        dmsg("Setting TCP_NODELAY: " + setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, nodelay, 4)); 
        dmsg("WSAGetLastError: " + WSAGetLastError());

        freeMemory(nodelay, 4);
    }
});
