rpc.exports = {
    getClassDetails: function (className) {
        return new Promise(function (resolve, reject) {
            try {
                if (!ObjC.available) {
                    return reject("Objective-C runtime is not available.");
                }

                const cls = ObjC.classes[className];
                if (!cls) {
                    return reject("Class " + className + " not found.");
                }

                console.log("[*] Extracting details for class: " + className);

                // Fetch methods (both instance and class methods)
                const instanceMethods = cls.$ownMethods;

                // Fetch protocols
                const protocols = cls.$protocols;

                // Fetch instance variables (iVars)
                const ivars = cls.$ivars;

                // Prepare the result
                const classDetails = {
                    className: className,
                    methods: instanceMethods,
                    protocols: protocols,
                    ivars: ivars
                };

                resolve(classDetails);

            } catch (error) {
                console.error("Error: " + error.message);
                reject(error.message);
            }
        });
    }
};

