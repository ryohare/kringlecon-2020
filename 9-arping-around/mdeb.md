cd debs
dpkg -x netcat-traditional_1.10-41.1ubuntu1_amd64.deb deb
chmod 755 deb
mkdir -p deb/DEBIAN
touch deb/DEBIAN/control
chmod 644 deb/DEBIAN/control
touch deb/DEBIAN/postinst
chmod 555 deb/DEBIAN/postinst

# mod control and postinst
# remake dpkg
chmod 755 DEBIAN
cd DEBIAN
dpkg-deb --build ../
