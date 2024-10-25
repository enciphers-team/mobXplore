rpc.exports = {
    getAppClasses: function () {
        return new Promise(function (resolve, reject) {
            try {
                if (!ObjC.available) {
                    return reject("Objective-C runtime is not available.");
                }

                // Get the main module of the currently running app
                const mainModule = Process.mainModule;
                console.log("[*] Main Module: " + mainModule.path);

                // Enumerate all loaded classes
                const allClasses = ObjC.enumerateLoadedClassesSync();

                resolve(allClasses);
            } catch (error) {
                console.error("Error: " + error.message);
                reject(error.message);
            }
        });
    }
};

