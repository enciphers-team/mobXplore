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

                // Fetch instance methods
                const instanceMethods = [];
                const instanceMethodEnumerator = cls.$methods;
                for (let i = 0; i < instanceMethodEnumerator.length; i++) {
                    instanceMethods.push(instanceMethodEnumerator[i].toString());
                }

                console.log("[*] Found " + instanceMethods.length + " instance methods.");

                // Fetch class methods
                const classMethods = [];
                const classObject = cls.$class;
                const classMethodEnumerator = classObject.$methods;
                for (let j = 0; j < classMethodEnumerator.length; j++) {
                    classMethods.push(classMethodEnumerator[j].toString());
                }

                console.log("[*] Found " + classMethods.length + " class methods.");

                // Fetch protocols
                const protocols = [];
                const protocolEnumerator = cls.$protocols;
                for (let k = 0; k < protocolEnumerator.length; k++) {
                    protocols.push(protocolEnumerator[k].toString());
                }

                console.log("[*] Found " + protocols.length + " protocols.");

                // Fetch instance variables (iVars)
                const ivars = [];
                const ivarEnumerator = cls.$ivars;
                for (let l = 0; l < ivarEnumerator.length; l++) {
                    ivars.push(ivarEnumerator[l].toString());
                }

                console.log("[*] Found " + ivars.length + " instance variables.");

                // Prepare the result
                const classDetails = {
                    className: className,
                    methods: {
                        instanceMethods: instanceMethods,
                        classMethods: classMethods
                    },
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

