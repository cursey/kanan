// Native functions used by this script.
var setsockopt = new NativeFunction(getProcAddress('Ws2_32.dll', 'setsockopt'),
    'int', ['uint', 'int', 'int', 'pointer', 'int'], 'stdcall');
var WSAGetLastError = new NativeFunction(getProcAddress('Ws2_32.dll', 'WSAGetLastError'),
    'int', [], 'stdcall');

// Constants used by this script.
var IPPROTO_TCP = 6;
var TCP_NODELAY = 0x0001;

// This is actually not the call to socket(), but the call to the wrapper 
// function Mabi's packer has created to hide the import. Intercepting this just
// as if it was socket() is fine, but I got NGS kicked when intercepting the
// actual socket() function (could have been a fluke I didn't do further 
// testing).
var socketCall = scan('E8 ? ? ? ? 8B F0 83 C4 0C 83 FE FF');
var socketOffset = Memory.readS32(socketCall.add(1));
var socketAddress = socketCall.add(5).toInt32() + socketOffset;

Interceptor.attach(ptr(socketAddress), {
    onLeave(retval) {
        // retval will be the result of the call to socket().
        var socket = retval.toInt32();
        var nodelay = allocateMemory(4);

        Memory.writeU32(nodelay, 1);

        dmsg("Socket: " + socket);
        dmsg("Setting TCP_NODELAY: " + setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, nodelay, 4)); 
        dmsg("WSAGetLastError: " + WSAGetLastError());

        freeMemory(nodelay, 4);
    }
})

// Calls socket().
/*var createSocketPtr = scan('55 8B EC 83 EC 08 56 57 8B 7D 0C 8B CF');

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
*/