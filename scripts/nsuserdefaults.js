if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function () {
        try {
            console.log("[*] Fetching NSUserDefaults...");

            // Get the shared NSUserDefaults for the app
            var userDefaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
            if (userDefaults === null) {
                console.log("[!] Unable to access NSUserDefaults.");
                return;
            }

            // Get all the keys stored in NSUserDefaults
            var allKeys = userDefaults.dictionaryRepresentation().allKeys();
            var count = allKeys.count();

            console.log("[*] Found " + count + " keys in NSUserDefaults.");

            // Collect the key-value pairs
            var userDefaultsData = [];
            for (var i = 0; i < count; i++) {
                var key = allKeys.objectAtIndex_(i).toString();
                var value = userDefaults.objectForKey_(key);

                // Create an object with key-value pair
                var entry = {
                    key: key,
                    value: value ? value.toString() : 'N/A'
                };
                userDefaultsData.push(entry);
            }

            // Log the results all at once
            send(userDefaultsData);
        } catch (error) {
            console.error("Error in fetching NSUserDefaults: " + error.message + " at line " + error.lineNumber);
        }
    });
} else {
    console.log("Objective-C runtime is not available.");
}

