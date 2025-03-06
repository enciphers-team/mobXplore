rpc.exports = {
    getInfoPlist: function () {
        var infoPlistPath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString() + "/Info.plist";
        var plistContent = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(infoPlistPath);
        
        if (!plistContent) {
            return {
                "error": "Failed to read Info.plist"
            };
        }

        // Convert NSDictionary to a JSON-compatible JavaScript object
        var jsonObject = {};
        var keys = plistContent.allKeys();
        for (var i = 0; i < keys.count(); i++) {
            var key = keys.objectAtIndex_(i).toString();
            var value = plistContent.objectForKey_(key);
            jsonObject[key] = value.toString();
        }

        return {
            "bundlePath": ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
            "infoPlistPath": infoPlistPath,
            "infoPlistContent": plistContent.toString(),  // Retaining original functionality
            "infoPlistJSON": jsonObject  // JSON representation for better readability
        };
    }
};

