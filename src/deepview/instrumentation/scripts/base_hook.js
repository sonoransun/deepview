'use strict';
// Base hook infrastructure for Deep View instrumentation
var DeepView = {
    hooks: {},

    addHook: function(name, target, callbacks) {
        var addr = Module.findExportByName(null, target);
        if (!addr) {
            send({type: 'hook_error', name: name, error: 'Function not found: ' + target});
            return;
        }
        this.hooks[name] = Interceptor.attach(addr, callbacks);
        send({type: 'hook_installed', name: name, target: target, address: addr.toString()});
    },

    removeHook: function(name) {
        if (this.hooks[name]) {
            this.hooks[name].detach();
            delete this.hooks[name];
        }
    },

    log: function(msg) {
        send({type: 'log', message: msg});
    }
};
