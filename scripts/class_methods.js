rpc.exports = {
    getClassMethods: function (className) {
        return new Promise(function (resolve, reject) {
            if (ObjC.available) {
                ObjC.schedule(ObjC.mainQueue, function () {
                    try {
                        console.log("[*] Fetching methods for class: " + className);

                        if (ObjC.classes.hasOwnProperty(className)) {
                            var cls = ObjC.classes[className];
                            var methods = cls.$methods || [];
                            console.log("[*] Found " + methods.length + " methods in class " + className);
                            resolve(methods);  // Return methods for the class
                        } else {
                            console.log("[!] Class " + className + " is not fully loaded.");
                            resolve([]);  // Return empty list if class isn't fully loaded
                        }

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

