if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function () {
        try {
            console.log("[*] Constructing keychain query...");

            // Create the query dictionary
            var query = ObjC.classes.NSMutableDictionary.dictionary();

            // Constants for keychain query
            const kSecClassGenericPassword = "genp"; // generic password
            const kSecClass = "class";
            const kSecMatchLimit = "m_Limit";
            const kSecMatchLimitAll = "m_LimitAll";
            const kSecReturnAttributes = "r_Attributes";
            const kSecReturnData = "r_Data";

            // Add query parameters
            query.setObject_forKey_(kSecClassGenericPassword, kSecClass);
            query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
            query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), kSecReturnAttributes);
            query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), kSecReturnData);

            console.log("[*] Query constructed: " + query);

            // Native function for SecItemCopyMatching
            var SecItemCopyMatching = new NativeFunction(
                Module.findExportByName('Security', 'SecItemCopyMatching'),
                'int',  // OSStatus return type
                ['pointer', 'pointer']  // Arguments: query dictionary, result pointer
            );

            console.log("[*] SecItemCopyMatching function located.");

            // Allocate memory for result pointer and initialize
            var resultPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(resultPtr, NULL);

            console.log("[*] Memory allocated for result pointer: " + resultPtr);

            // Call SecItemCopyMatching
            var status = SecItemCopyMatching(query.handle, resultPtr);
            console.log("[*] SecItemCopyMatching call status: " + status);

            if (status === 0) {  // 0 means success
                var resultObj = new ObjC.Object(Memory.readPointer(resultPtr));
                console.log("[*] Keychain items retrieved: " + resultObj.count() + " items found.");

                // Collect keychain data into an array
                var keychainData = [];
                var enumerator = resultObj.objectEnumerator();
                var item;

                while ((item = enumerator.nextObject()) !== null) {
                    var entry = {
                        account: item.objectForKey_("acct") ? item.objectForKey_("acct").toString() : 'N/A',
                        service: item.objectForKey_("svce") ? item.objectForKey_("svce").toString() : 'N/A',
                        data: item.objectForKey_("v_Data") ? item.objectForKey_("v_Data").toString() : 'N/A'
                    };
                    keychainData.push(entry);
                }

                // Output all collected data at once
                console.log("[*] Keychain data: " + JSON.stringify(keychainData, null, 2));
            } else {
                console.log("[!] No keychain items found or access denied. Status: " + status);
            }
        } catch (error) {
            console.error("Error in main function: " + error.message + " at line " + error.lineNumber);
        }
    });
} else {
    console.log("Objective-C runtime is not available.");
}

