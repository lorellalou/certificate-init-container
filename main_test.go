// Package main_test is default test package for the main package.
package main_test


import (
	"encoding/pem"
	"github.com/pavel-v-chernykh/keystore-go"
	"log"
	"os"
	"time"
	"testing"
)

const testKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAtyKw7ZrCXEOzw4h7POuC1bFqC0Ubx3Bcq000doI7/nfyoT+z
tKec0HrDPJMOTpjjZxuPR5tnE+rvSBX3k9yX47zWI5JBdPqrZkq+T1ephnfHJHX+
NRBR4c2xgGYhFuMWcX7h5mY3gSnLzKY9/o3/Kcf3kZ7HYfz+SFL1lIK4r7ByITOo
KSG1LDvScRfK7ecvh29cyaCzv2Ft8+9ebni4BsiB+XQj0Roq9gc/CjSeqo1nD7QD
fWwAUtknJTVSgBer0RDICnfKlU0b2LvAlLCAo4Ul0CoJj4uktreED1GaDdJI1Lqg
5W7FE+OJI7CUlgL7sFeP4vyqIvcSMWg5qdS1HQIDAQABAoIBABhCDx+aFU61ZRVs
ea6LH6yAsKRHhjN3zb6fHmjoPVwqtUfosTwny5zN9hiK/iUpGU4qF2OL0S6ROxrY
VhAO80umUtMpZ2RAY/3LvsOxv/Hg4c8RlhefTslTPsTcQlvOvsVP4kprlcSVLbqw
9ptGYds98qwmVRDEu0YHPyJp4l7bDhAvsrPS+hdYhYqMvogAHMIL3oYU0jtxyB5O
+goISUzRauUvTpZLuFqn4Xx0Rf2pEeHDBaLyiSrp8GFpyH9tU5955TE1cygfWwXM
5sbLb6BWkeDLth+JOUki4EGFbWDPmFOU5ZzmvoHpE1qrmW15ysJ3hfHgyzdMe2/r
UJYUZ6ECgYEA0lT/dDroVRJGPOPfUqeNr4L+I4T2eF63YxOfpBTvdLNFzPO9HKuu
CV94zIDjvoR6xPS3e/BPAFw1qAr6IdrJlC4jD9WKHrB1wDgAOIatt8xLak8MyDU3
0YODvzpjlDb7gYpfZfmz9g33+XADkK5/ZvS+FnBz6za6j9FrAgNwNkkCgYEA3uYD
shJyaTRGiWZYQd+03cKpaguuQ0XjHjB2LBdaCkpCVu60//ZglOG3/oOaHWaYLRDY
RmFBzLJ0kdj3OAqbeMgC5ya5lPaq2owA51hKBOr6Ur8Gdk8ccti5HBR9SWSgTpV9
UINieZoHmSVjs3RKkgqnLMq3TqcfFhtBh7PtuDUCgYB51xsT7Xvgq/FcHHSloMIG
xc8KLF/KYrPBBQEZP7dm1uK8UwVdsmXisBd9/7vuBThJF6midhaNktzSN2mmauMS
n5dX+M9F79qGOuqF1B6VthaJwrkY0RtAlvqer+g3V5Jh/BI/NGL3Sig3qpemHC9Z
KLVkske0HcP8w8dFJ1C9YQKBgD1NNSb8O8sDPYL8SrmTNMLojn9DxyFpTxU2bsmh
gnniAmy2KcFbmSRZD6lHuFLtrFx4jYKNrPMHAVg7O4KGKEwHdgTseY2maUbByl3V
wkWn+kBXmQdgqopLYF2ApRRSQGRcaKKD/8lBu2U7CziHexq/I0sGVXOkMsB5roQL
0A0hAoGAUX0+wBn4ZWP4O7Zrqdn+MuHMBejzQ7T4LRNCJbWE/hP5u7IsprEjhQYJ
CXr3GTgwjktLeq4OZefpNHbz/xgXxQj5Jn8m4W+5p0XTH2uOwdT17R8AXA0pEyYb
rH5wlOeLE0V4U+ILSk9UcpkNz2RFqxrEyo/ctgTPIVEAAWHUgQ8=
-----END RSA PRIVATE KEY-----
`

const testCert = `
-----BEGIN CERTIFICATE-----
MIID1zCCAr+gAwIBAgIUYO7oba+9OEbpmKkKIYJe4xaxy4MwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAxMNY2x1c3Rlci5sb2NhbDAeFw0xODEwMTAxODI0MDVaFw0x
OTAxMDgxODI0MzVaMEIxDjAMBgNVBAsTBWthZmthMTAwLgYDVQQDEycxMC00MC0y
LTQ0Lmt1YmUta2Fma2EucG9kLmNsdXN0ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC3IrDtmsJcQ7PDiHs864LVsWoLRRvHcFyrTTR2gjv+
d/KhP7O0p5zQesM8kw5OmONnG49Hm2cT6u9IFfeT3JfjvNYjkkF0+qtmSr5PV6mG
d8ckdf41EFHhzbGAZiEW4xZxfuHmZjeBKcvMpj3+jf8px/eRnsdh/P5IUvWUgriv
sHIhM6gpIbUsO9JxF8rt5y+Hb1zJoLO/YW3z715ueLgGyIH5dCPRGir2Bz8KNJ6q
jWcPtAN9bABS2SclNVKAF6vREMgKd8qVTRvYu8CUsICjhSXQKgmPi6S2t4QPUZoN
0kjUuqDlbsUT44kjsJSWAvuwV4/i/Koi9xIxaDmp1LUdAgMBAAGjge4wgeswDgYD
VR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNV
HQ4EFgQUEYVrMgY9Fk3JPIZ8T/Tf7iQSE4owHwYDVR0jBBgwFoAUQsZ6mGUwu82s
ehgvQ2+NIvOCQb4wegYDVR0RBHMwcYInMTAtNDAtMi00NC5rdWJlLWthZmthLnBv
ZC5jbHVzdGVyLmxvY2FsgjRrYWZrYS1jcC1rYWZrYS1oZWFkbGVzcy5rdWJlLWth
ZmthLnN2Yy5jbHVzdGVyLmxvY2FshwQKKAIshwR/AAABhwQKhAADMA0GCSqGSIb3
DQEBCwUAA4IBAQCfeRfTeDh9fQ6RPB9twQjNwGYUqBmugE6MAvoe6w9BkRTeFTHb
inWbCT5bAbGgmWOmMdd6gHZNFQrquhFDEdOcFhpUot+trdKnTqDbFBdT5O6vWSsS
RP2OUAihaiBPjR5XSxQOHAjc90VLQAKEAXX6pHlTiSVOUcCWKQKTdgguooRBIKTO
+CLsa6G+8NafXj//F7o0/7rxjA8J688VTes6TA/LHc19vb6/ic38i3w9pZpvcRuB
LQ7fcFUMDNviOHmo8YYWrz2X0wr+1AcY/QHi7LWLKjNpV6zXYP+yS23PhxN6IkwI
0It4vWShQYHEfpvSVqWB0pw6niExPs/jn9qd
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIUQZxqlDb4tkTVwL5fjGxSbbDN4wIwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAxMNY2x1c3Rlci5sb2NhbDAeFw0xODEwMDIxMjA5NTRaFw0x
OTAzMzExMjEwMjRaMBgxFjAUBgNVBAMTDWNsdXN0ZXIubG9jYWwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoEIqiK9Y/Jb9sP4rF5pw3oiDdY442T2zw
pfv2yHQfg/NR09jiksfeLMaIPtx1u5BXwP/apJbdyKhKXkx4KnjvInnmzAkf2IvQ
Mh5mCy0IX18Ng78asqMYMj55NraWbLcSEepd2Baz0xvZPdotu0lcaQKVK2+FaTSp
M8FE1LDOwmoNtYLK7T8r+j681O8HSuSlGvOu4uU3TcvvheZy7hbYR2GAGzHG/YD/
b9/SUhzPSXGOvF1xBeuehPkD1qxXZLyRvuHUxZX6DRtertGftJrtUjG/gIPDDaxm
fDAK3M+b7LV6yY7Giie9ZAQeEZpIhYE8bdZrG6jraDLCZkQRWcW/AgMBAAGjfTB7
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRCxnqY
ZTC7zax6GC9Db40i84JBvjAfBgNVHSMEGDAWgBRCxnqYZTC7zax6GC9Db40i84JB
vjAYBgNVHREEETAPgg1jbHVzdGVyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQDA
iS+D2nqTK92CvVV4zGTR70ufhNhBfKX0I12CLr5qlnUMQra4PYLmBSkOYzuKk+P2
rH/VUh9Mc1/Sk5pcbFtwP8yPwH/YK6J5XcIUTmQ3w9eE9SZbld43VmSCgMqT2dEd
syeq6KOUeKzdsjkogv54/9pneztepHofIoJtZOIcI666gi0ZgQqgP5h9t75i7qOQ
aqfi/hGSHB5Bm6Qf2oZeaPeTU8ElqhWSI02rQmHRX2VBjQ3sJxr5QTMjHLdpcIMG
G98Ae5I+0ssThNRINFncJ2V1h5NPSEcD9RSBFcmRX3GkdHoxU2f2I5hzvktJJu+p
cdau/SfhGclIc8TlPPKJ
-----END CERTIFICATE-----
`

// TestDefault is a placeholder test so CI passes.
func TestDefault(t *testing.T) {

	var buf []byte = []byte(testCert)
	var block *pem.Block
	var certificates []keystore.Certificate
	// loop over pem encoded data
	for len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil {
			log.Fatal("invalid PEM data")
		}
		certificates = append(certificates, 
			keystore.Certificate{
				Type: "X509",
				Content: block.Bytes,	
			})
		
	}

	// Load the configuration file
	keyStore := keystore.KeyStore{
		"alias": &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			PrivKey: []byte(testKey),
			CertChain: certificates,	
		},
	}

	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)
	writeKeyStore(keyStore, "keystore.jks", password)

	ks := readKeyStore("keystore.jks", password)

	entry := ks["alias"]
	privKeyEntry := entry.(*keystore.PrivateKeyEntry)
	log.Printf("%v", string(privKeyEntry.PrivKey))


}

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	defer o.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatal(err)
	}
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}
