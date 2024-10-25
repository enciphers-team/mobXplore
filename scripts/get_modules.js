rpc.exports = {
    getModules: function () {
        return new Promise(function (resolve, reject) {
            try {
                console.log("[*] Extracting module names...");

                // Enumerate all loaded modules in the app
                var modules = Process.enumerateModules();

                // Extract module names
                var moduleNames = modules.map(function (module) {
                    return module.name;
                });

                console.log("[*] Found " + moduleNames.length + " modules.");

                // Send the module names back to Python
                resolve(moduleNames);

            } catch (error) {
                console.error("Error: " + error.message);
                reject(error.message);
            }
        });
    }
};

