rpc.exports = {
    listAppFiles: function () {
        var NSFileManager = ObjC.classes.NSFileManager.defaultManager();
        var appPath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        var fileStructure = {};

        function listFilesRecursively(path, relativePath) {
            var contents = NSFileManager.contentsOfDirectoryAtPath_error_(path, NULL);
            if (contents) {
                var fileList = [];
                for (var i = 0; i < contents.count(); i++) {
                    var fileName = contents.objectAtIndex_(i).toString();
                    var fullPath = path + "/" + fileName;
                    var relativeFolderPath = relativePath.replace(appPath, "").replace(/^\//, "");

                    var isDirectoryPtr = Memory.alloc(Process.pointerSize);
                    if (NSFileManager.fileExistsAtPath_isDirectory_(fullPath, isDirectoryPtr)) {
                        var isDirectory = isDirectoryPtr.readU8();
                        if (isDirectory) {
                            listFilesRecursively(fullPath, relativeFolderPath + (relativeFolderPath ? "/" : "") + fileName);
                        } else {
                            fileList.push(fileName);
                        }
                    }
                }
                fileStructure[relativePath] = fileList;
            }
        }

        listFilesRecursively(appPath, ""); // Start with appPath as base

        return fileStructure;
    }
};
