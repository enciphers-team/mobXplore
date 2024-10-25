rpc.exports = {
    getClassesAndMethods: function () {
        return new Promise(function (resolve, reject) {
            if (ObjC.available) {
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        console.log("[*] Extracting class names and methods for the app...");

                        // Get the main module (binary)
                        var mainModule = Process.enumerateModules()[0];
                        var appModuleName = mainModule.name;

                        console.log("[*] App module: " + appModuleName);

                        // Log all loaded classes to check if we are filtering correctly
                        var allClasses = ObjC.enumerateLoadedClassesSync();
                        var appClasses = [];

                        console.log("[*] Listing all loaded classes...");
                        for (var className in allClasses) {
                            console.log("Class: " + className);  // Debug log to ensure we are seeing classes
                            // Try to filter by prefix (if appModuleName doesn't work, try a prefix-based approach)
                            if (className.includes(appModuleName.split('.')[0])) {
                                appClasses.push(className);
                            }
                        }

                        console.log("[*] Found " + appClasses.length + " classes in the app.");

                        if (appClasses.length === 0) {
                            console.log("[!] No classes found. Check if the filtering logic is too strict.");
                        }

                        // Collect class names and their methods
                        var classData = appClasses.map(function (className) {
                            var cls = ObjC.classes[className];
                            if (cls) {
                                return {
                                    className: className,
                                    methods: cls.$methods || []  // Fallback to ensure methods are extracted
                                };
                            } else {
                                console.log("[!] Warning: Class " + className + " is not fully loaded.");
                                return {
                                    className: className,
                                    methods: []  // Return an empty list if the class isnt fully loaded
                                };
                            }
                        });

                        console.log("[*] Returning class and method data.");
                        resolve(classData);

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

