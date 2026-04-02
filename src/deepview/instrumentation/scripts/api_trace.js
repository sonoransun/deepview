'use strict';
// General OS API tracing

var apis = ['open', 'close', 'read', 'write', 'connect', 'send', 'recv',
            'socket', 'bind', 'listen', 'accept', 'mmap', 'mprotect',
            'execve', 'fork', 'clone'];

apis.forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                send({
                    type: 'api_call',
                    function: name,
                    pid: Process.id,
                    tid: this.threadId,
                    args: [args[0].toString(), args[1].toString(), args[2].toString()]
                });
            },
            onLeave: function(retval) {
                send({
                    type: 'api_return',
                    function: name,
                    pid: Process.id,
                    retval: retval.toInt32()
                });
            }
        });
    }
});
