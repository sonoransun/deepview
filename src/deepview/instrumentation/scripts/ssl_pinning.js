'use strict';
// SSL certificate pinning bypass for analysis

// iOS/macOS - SecTrustEvaluate
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
if (SecTrustEvaluate) {
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, error) {
        send({type: 'ssl_bypass', method: 'SecTrustEvaluateWithError'});
        return 1; // Always trust
    }, 'bool', ['pointer', 'pointer']));
}

// Android/Linux - SSL_CTX_set_verify
var SSL_CTX_set_verify = Module.findExportByName('libssl.so', 'SSL_CTX_set_verify');
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function(args) {
            args[1] = ptr(0); // Set verify mode to SSL_VERIFY_NONE
            send({type: 'ssl_bypass', method: 'SSL_CTX_set_verify'});
        }
    });
}
