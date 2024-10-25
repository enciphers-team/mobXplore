rpc.exports = {
    getInfoPlist: function () {
        // Fetch the Info.plist file contents
        var infoPlistPath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString() + "/Info.plist";
        var plistContent = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(infoPlistPath);
        return {
            "bundlePath": ObjC.classes.NSBundle.mainBundle().bundlePath().toString(),
            "infoPlistPath": infoPlistPath,
            "infoPlistContent": plistContent.toString()
        };
    }
};

