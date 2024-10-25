rpc.exports = {
    getClassNames: function () {
        return new Promise(function (resolve, reject) {
            if (ObjC.available) {
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        console.log("[*] Extracting class names for the app...");

                        // Get the main module (binary)
                        var mainModule = Process.enumerateModules()[0];
                        var appModuleName = mainModule.name;

                        console.log("[*] App module: " + appModuleName);

                        // Log all loaded classes
                        var allClasses = ObjC.enumerateLoadedClassesSync();
                        var appClasses = [];

                        console.log("[*] Listing all loaded classes...");
                        for (var className in allClasses) {
                            console.log("Class: " + className);  // Debug log to ensure we are seeing classes
                            
                            // Filter classes based on the app module name
                            if (className.includes(appModuleName.split('.')[0])) {
                                appClasses.push(className);
                            }
                        }

                        console.log("[*] Found " + appClasses.length + " classes in the app.");

                        if (appClasses.length === 0) {
                            console.log("[!] No classes found. Check if the filtering logic is too strict.");
                        }

                        // Return only the class names
                        resolve(appClasses);

                    } catch (error) {
                        console.error("Error: " + error.message);
                        reject(error.message);
                    }
                });
            } else {
                reject("Objective-C runtime is not available.");
            }
        });
    }
};

