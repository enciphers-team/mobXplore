rpc.exports = {
    readFileContents: function (folderName, fileName) {
        var NSFileManager = ObjC.classes.NSFileManager.defaultManager();
        var appPath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        var targetPath = folderName ? appPath + "/" + folderName + "/" + fileName : appPath + "/" + fileName;
        if (folderName === 'base_path'){
            targetPath = appPath + "/" + fileName
        }
        if (!NSFileManager.fileExistsAtPath_(targetPath)) {
            return "File not found.";
        }

        var NSData = ObjC.classes.NSData;
        var fileData = NSData.dataWithContentsOfFile_(targetPath);
        console.log(fileData);
        if (!fileData || fileData.length() === 0) {
            return "File is empty or could not be read.";
        }

        var NSString = ObjC.classes.NSString;
        var fileContents = NSString.alloc().initWithData_encoding_(fileData, 4); // 4 = NSUTF8StringEncoding

        if (fileContents) {
            return fileContents.toString();
        }

        var encodings = [1, 3, 9, 30]; // ASCII, Latin1, UTF-16, UTF-32
    for (var i = 0; i < encodings.length; i++) {
        fileContents = NSString.alloc().initWithData_encoding_(fileData, encodings[i]);
        if (fileContents) {
            return fileContents.toString();
        }
    }

    // If all else fails, convert to hex
    var bytes = fileData.bytes();
    var length = fileData.length();
    var rawData = Memory.readByteArray(bytes, length);

    if (rawData) {
        try {
            var utf8Decoder = new TextDecoder("utf-8");
            var decodedText = utf8Decoder.decode(new Uint8Array(rawData));
            return decodedText || "Binary data (hex): " + Array.from(new Uint8Array(rawData)).map(b => b.toString(16).padStart(2, "0")).join(" ");
        } catch (e) {
            return "Binary data (hex): " + Array.from(new Uint8Array(rawData)).map(b => b.toString(16).padStart(2, "0")).join(" ");
        }
    }

    return "Error reading file.";
    }
};
