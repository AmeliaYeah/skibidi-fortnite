
function bypassSleep(moduleName, funcName) {
    /// modulename is KERNEL32.DLL or KERNELBASE.DLL, funcName is Sleep
    var addr = Module.findExportByName(moduleName, funcName); 
    // find the sleep function in the module, is Frida API
    if (addr) {
        Interceptor.replace(addr, new NativeCallback(function(delay) { // replace sleep with a new function
            // we use interceptor.replace to override target func
            // new NativeCallback: defines new function, receives delay as parameter, same as sleep
            console.log("Bypassing " + funcName + " from " + moduleName + ". Original delay: " + delay.toInt32() + " ms");
            // Return immediately - do nothing
            return;
        }, 'void', ['uint32']));
        console.log("Replaced " + moduleName + "!" + funcName);
    } else {
        console.log("Could not find " + moduleName + "!" + funcName);
    }
}

// Replace Sleep in both modules:
bypassSleep("kernel32.dll", "Sleep");
bypassSleep("kernelbase.dll", "Sleep");