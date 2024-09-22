var do_dlopen = null;
var call_constructor = null;

// Find do_dlopen and call_constructor symbols
Process.findModuleByName("linker64").enumerateSymbols().forEach(function(symbol) {
    if (symbol.name.indexOf("do_dlopen") >= 0) {
        do_dlopen = symbol.address;
    }
    if (symbol.name.indexOf("call_constructor") >= 0) {
        call_constructor = symbol.address;
    }
});

var lib_loaded = 0;

// Attach to do_dlopen
var do_dlopen_interceptor = Interceptor.attach(do_dlopen, function() {
    var library_path = this.context.x0.readCString(); 
    console.log("\x1b[36m[*] do_dlopen called with library: " + library_path + "\x1b[0m");
    if (library_path.indexOf("libflutter.so") >= 0) {
        console.log("\x1b[32m[*] libflutter.so detected, attaching to call_constructor\x1b[0m");

        // Attach to call_constructor
        var call_constructor_interceptor = Interceptor.attach(call_constructor, function() {
            console.log("\x1b[33m[*] Checking if libflutter is fully loaded...\x1b[0m");
            if (lib_loaded === 0) {
                lib_loaded = 1;
                var module = Process.findModuleByName("libflutter.so");
                if (module) {
                    console.log("\x1b[32m[+] libflutter is loaded at " + module.base + "\x1b[0m");
                    var address = module.base.add(0x3E0F74);
                    console.log("\x1b[32m[*] Trying to attach to session_verify_cert_chain at " + address + "\x1b[0m");

                    session_verify_cert_chain(address);

                    // Detach the interceptor after executing the target function
                    call_constructor_interceptor.detach();
                    do_dlopen_interceptor.detach();
                } else {
                    console.log("\x1b[31m[-] Error: libflutter.so not found.\x1b[0m");
                }
            }
        });
    }
});

function session_verify_cert_chain(address) {
    // Parsing and printing the first 10 instructions
    console.log("\x1b[36m[*] First 10 instructions at " + address + ":\x1b[0m");
    for (let i = 0; i < 10; i++) {
        let instrPtr = ptr(address).add(i * 4);
        let instrHex = instrPtr.readU32().toString(16);
        console.log("\x1b[34m0x" + instrHex.padStart(8, '0') + "\x1b[0m");
    }
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("\x1b[32m[*] session_verify_cert_chain called\x1b[0m");
        },
        onLeave: function(retval) {
            console.log("\x1b[31m[+] session_verify_cert_chain retval before: " + retval + "\x1b[0m");
            retval.replace("0x1");
            console.log("\x1b[32m[+] session_verify_cert_chain modified retval: " + retval + "\x1b[0m");
        }
    });
}
