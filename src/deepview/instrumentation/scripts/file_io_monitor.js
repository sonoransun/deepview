'use strict';
// Monitor file I/O operations

var open_func = Module.findExportByName(null, 'open');
if (open_func) {
    Interceptor.attach(open_func, {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
            this.flags = args[1].toInt32();
        },
        onLeave: function(retval) {
            send({
                type: 'file_open',
                pid: Process.id,
                path: this.path,
                flags: this.flags,
                fd: retval.toInt32()
            });
        }
    });
}

var read_func = Module.findExportByName(null, 'read');
if (read_func) {
    Interceptor.attach(read_func, {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            this.count = args[2].toInt32();
        },
        onLeave: function(retval) {
            send({type: 'file_read', pid: Process.id, fd: this.fd, requested: this.count, actual: retval.toInt32()});
        }
    });
}
