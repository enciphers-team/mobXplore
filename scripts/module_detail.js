rpc.exports = {
    getModuleDetails: function (moduleName) {
        return new Promise(function (resolve, reject) {
            try {
                console.log("[*] Extracting details for module: " + moduleName);

                // Find the module by name
                var module = Process.findModuleByName(moduleName);
                if (!module) {
                    throw new Error("Module " + moduleName + " not found.");
                }

                console.log("[*] Found module: " + moduleName + " at base address: " + module.base);

                // Collect module details
                var moduleDetails = {
                    name: module.name,
                    base: module.base ? module.base.toString() : "N/A",
                    size: module.size ? module.size : "N/A",
                    importsByModule: {},
                    exports: [],
                    symbols: []
                };

                // Enumerate imports and group by module
                var imports = Module.enumerateImports(moduleName);
                imports.forEach(function (imp) {
                    var impModule = imp.module || "Unknown";
                    if (!moduleDetails.importsByModule[impModule]) {
                        moduleDetails.importsByModule[impModule] = [];  // Initialize the list for this module
                    }

                    moduleDetails.importsByModule[impModule].push({
                        name: imp.name || "N/A",
                        address: imp.address ? imp.address.toString() : "N/A"
                    });
                });

                console.log("[*] Grouped imports by module.");

                // Enumerate exports
                var exports = Module.enumerateExports(moduleName);
                exports.forEach(function (exp) {
                    moduleDetails.exports.push({
                        name: exp.name || "N/A",
                        address: exp.address ? exp.address.toString() : "N/A",
                        type: exp.type || "N/A"
                    });
                });

                console.log("[*] Found " + moduleDetails.exports.length + " exports.");

                // Enumerate symbols, filtering out those with type 'undefined' or name 'redacted'
                var symbols = Module.enumerateSymbols(moduleName);
                symbols.forEach(function (sym) {
                    // Filter out symbols with type 'undefined' or name 'redacted'
                    if (sym.type !== "undefined" && sym.name !== "<redacted>") {
                        moduleDetails.symbols.push({
                            name: sym.name || "N/A",
                            address: sym.address ? sym.address.toString() : "N/A",
                            type: sym.type || "N/A"
                        });
                    }
                });

                console.log("[*] Found " + moduleDetails.symbols.length + " symbols after filtering.");

                // Send the result back
                resolve(moduleDetails);

            } catch (error) {
                console.error("Error: " + error.message);
                reject(error.message);
            }
        });
    }
};

