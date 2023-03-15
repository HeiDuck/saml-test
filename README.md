# saml-test

keytool -genkeypair -alias lifecycle -keypass 123456 -keyalg RSA -keystore okta.jks

keytool -import -v -trustcacerts -keystore okta.jks -file okta.cert