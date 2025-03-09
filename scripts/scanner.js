rpc.exports = {
    scanner: function () {
        var infoPlistPath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString() + "/Info.plist";
        var plistContent = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(infoPlistPath);
        
        if (!plistContent) {
            return {
                "error": "Failed to read Info.plist"
            };
        }

        // Function to recursively convert NSDictionary and NSArray to JSON-compatible objects
        function convertToJson(obj) {
            if (obj.isKindOfClass_(ObjC.classes.NSDictionary)) {
                var result = {};
                var keys = obj.allKeys();
                for (var i = 0; i < keys.count(); i++) {
                    var key = keys.objectAtIndex_(i).toString();
                    var value = obj.objectForKey_(key);
                    result[key] = convertToJson(value);  // Recursive call
                }
                return result;
            } else if (obj.isKindOfClass_(ObjC.classes.NSArray)) {
                var resultArray = [];
                for (var j = 0; j < obj.count(); j++) {
                    resultArray.push(convertToJson(obj.objectAtIndex_(j)));  // Recursive call
                }
                return resultArray;
            } else {
                return obj.toString();  // Convert primitive types to string
            }
        }

        return {
            "bundlePath": ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
            "infoPlistPath": infoPlistPath,
            "infoPlistContent": plistContent.toString(),  // Retaining original functionality
            "infoPlistJSON": convertToJson(plistContent)  // Recursively convert to JSON-compatible object
        };
    }
    
};
