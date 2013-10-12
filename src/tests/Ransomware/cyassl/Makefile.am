SUBDIRS = src ctaocrypt examples testsuite
EXTRA_DIST = cyassl.dsp cyassl.dsw certs/*.pem certs/*.der certs/*.txt \
    lib/dummy cyassl.sln cyassl.vcproj cyassl-iphone.xcodeproj/project.pbxproj

basic:
	cd src; make; cd ../testsuite; make; cd ../

openssl-links:
	cd lib; ln -s ../src/.libs/libcyassl.a libcrypto.a; \
    ln -s ../src/.libs/libcyassl.a libssl.a; cd ../
    
