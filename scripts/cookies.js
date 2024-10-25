if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function () {
        try {
            console.log("[*] Fetching cookies...");

            // Get the shared cookie storage for the app
            var cookieStorage = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
            if (cookieStorage === null) {
                console.log("[!] Unable to access cookie storage.");
                return;
            }

            // Get all cookies
            var cookies = cookieStorage.cookies();
            var count = cookies.count();

            console.log("[*] Found " + count + " cookies.");

            // Collect the cookie details
            var cookieData = [];
            for (var i = 0; i < count; i++) {
                var cookie = cookies.objectAtIndex_(i);
                var cookieEntry = {
                    name: cookie.name().toString(),
                    value: cookie.value().toString(),
                    domain: cookie.domain().toString(),
                    path: cookie.path().toString(),
                    expiresDate: cookie.expiresDate() ? cookie.expiresDate().toString() : 'Session',
                    secure: cookie.isSecure() ? 'Yes' : 'No'
                };
                cookieData.push(cookieEntry);
            }

            // Log the collected cookies all at once
            console.log(cookieData);

        } catch (error) {
            console.error("Error in fetching cookies: " + error.message + " at line " + error.lineNumber);
        }
    });
} else {
    console.log("Objective-C runtime is not available.");
}

