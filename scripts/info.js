if (ObjC.available) {
    try {
        // Create a result object to store the bundle path, Info.plist path, and Info.plist content
        var result = {};

        // Get the bundle path of the currently running application
        var bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        result['bundlePath'] = bundlePath;

        // Construct the Info.plist path
        var infoPlistPath = bundlePath + "/Info.plist";
        result['infoPlistPath'] = infoPlistPath;

        // Read the Info.plist file
        var fileManager = ObjC.classes.NSFileManager.defaultManager();
        var plistData = fileManager.contentsAtPath_(infoPlistPath);

        if (plistData !== null) {
            // Parse the plist data
            var plistContent = ObjC.classes.NSPropertyListSerialization.propertyListWithData_options_format_error_(
                plistData,
                0,  // options (0 means no special options)
                NULL,  // format (NULL means we'll accept any format)
                NULL  // error (NULL means we ignore errors)
            );

            if (plistContent) {
                result['infoPlistContent'] = plistContent.toString();
            } else {
                result['infoPlistContent'] = "Failed to parse Info.plist";
            }
        } else {
            result['infoPlistContent'] = "Failed to read Info.plist";
        }

        // Send the result object to Python as a single message
        send(result);

    } catch (e) {
        send({"error": e.message});
    }
} else {
    send({"error": "Objective-C runtime is not available!"});
}

