# Objective 3 - Point-of-Sale Password Recovery 
This challenge is about extracting a secret from an electron application which is provided as part of the challenge. This is done by extracting the contents or the executable file provided as part of the challenge. Once done, extracting then the app data which is 7zip zipped. On ce this is unzipped, the source code of the actual app can be inspected and the password can be recovered.
## Enumeration
The file is provided for analysis from the challenge. It is a PE file named `santa-shop.exe`. It can be extracted to see it's contents using p7zip on a mac.
```bash
mkdir santa-shop
cp santa-shop.exe santa-shop/
cd santa-shop.exe
7z x santa-shop.exe
```
The resulting file structure makes it look like the application is an electron contained in the file, `app-64.7z` within the unzipped `$PLUGINS` directory.

```bash
cd \$PLUGINS
7z x app-64.7z
find .
```
## Investigating the Electron App
Now that the app has been decompressed, secrets can be looked for in the application. The electron application is contained within the app.asar file within the resources directory. Stepping through this file via via strings, the password can be discovered.
```bash
strings resources/app.asar | less
```
![Password in Application Hint](img/password-hint.png)
![Password in Application](img/password.png)