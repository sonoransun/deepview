'use strict';
// Monitor process creation and termination

if (Process.platform === 'linux') {
    var execve = Module.findExportByName(null, 'execve');
    if (execve) {
        Interceptor.attach(execve, {
            onEnter: function(args) {
                send({
                    type: 'process_exec',
                    pid: Process.id,
                    tid: this.threadId,
                    filename: args[0].readUtf8String()
                });
            }
        });
    }

    var fork_addr = Module.findExportByName(null, 'fork');
    if (fork_addr) {
        Interceptor.attach(fork_addr, {
            onLeave: function(retval) {
                send({type: 'process_fork', pid: Process.id, child_pid: retval.toInt32()});
            }
        });
    }
}
