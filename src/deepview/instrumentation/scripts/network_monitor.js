'use strict';
// Monitor network operations

var connect_func = Module.findExportByName(null, 'connect');
if (connect_func) {
    Interceptor.attach(connect_func, {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            var sockaddr = args[1];
            var family = sockaddr.readU16();
            if (family === 2) { // AF_INET
                var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                var ip = sockaddr.add(4).readU8() + '.' + sockaddr.add(5).readU8() + '.' +
                         sockaddr.add(6).readU8() + '.' + sockaddr.add(7).readU8();
                this.addr = ip;
                this.port = port;
            }
        },
        onLeave: function(retval) {
            if (this.addr) {
                send({
                    type: 'network_connect',
                    pid: Process.id,
                    fd: this.fd,
                    address: this.addr,
                    port: this.port,
                    result: retval.toInt32()
                });
            }
        }
    });
}
