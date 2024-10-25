// Get the app bundle path and read Info.plist
if (ObjC.available) {
    try {
        // Get the bundle path of the currently running application
        var bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();

        // Construct the Info.plist path
        var infoPlistPath = bundlePath + "/Info.plist";

        console.log("App Bundle Path: " + bundlePath);
        console.log("Info.plist Path: " + infoPlistPath);

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
                console.log("Info.plist Content: " + plistContent.toString());
            } else {
                console.log("Failed to parse Info.plist");
            }
        } else {
            console.log("Failed to read Info.plist");
        }
    } catch (e) {
        console.log("Error: " + e.message);
    }
} else {
    console.log("Objective-C runtime is not available!");
}

