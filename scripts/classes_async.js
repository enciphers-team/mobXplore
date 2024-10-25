rpc.exports = {
    getClassesAndMethods: function () {
        return new Promise(function (resolve, reject) {
            if (ObjC.available) {
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        console.log("[*] Automatically extracting class names and methods for the attached app...");

                        // Get the main module (the app's binary)
                        var mainModule = Process.enumerateModules()[0]; // The first module is usually the app itself
                        var appModulePath = mainModule.path;
                        var appModuleName = mainModule.name;

                        console.log("[*] Found app module: " + appModuleName + " at path: " + appModulePath);

                        // Filter classes that are from the app module
                        var allClasses = ObjC.enumerateLoadedClassesSync();
                        var appClasses = [];

                        for (var moduleName in allClasses) {
                            if (moduleName.indexOf(appModuleName) >= 0) {
                                appClasses = appClasses.concat(allClasses[moduleName]);
                            }
                        }

                        console.log("[*] Found " + appClasses.length + " classes in the target app.");

                        // Collect class names and their methods
                        var classData = [];

                        appClasses.forEach(function (className) {
                            if (ObjC.classes.hasOwnProperty(className)) {
                                var cls = ObjC.classes[className];
                                if (cls) {
                                    // Get methods for the class
                                    var methods = cls.$methods || [];
                                    var classEntry = {};
                                    classEntry[className] = methods;
                                    classData.push(classEntry);
                                } else {
                                    console.log("[!] Warning: Class " + className + " is not fully loaded.");
                                }
                            }
                        });

                        // Resolve the promise with class data
                        resolve(classData);

                    } catch (error) {
                        console.error("Error: " + error.message + " at line " + error.lineNumber);
                        reject(error.message);
                    }
                });
            } else {
                console.log("Objective-C runtime is not available.");
                reject("Objective-C runtime is not available.");
            }
        });
    }
};

