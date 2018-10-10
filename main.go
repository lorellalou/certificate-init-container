// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"bufio"
	"bytes"
	
	"crypto/x509"
	
	
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	cmv1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	
	"github.com/pavel-v-chernykh/keystore-go"
)

var (
	additionalDNSNames string
	issuerName         string
	issuerKind         string
	secretName         string
	clusterDomain      string
	hostname           string
	namespace          string
	podIP              string
	podName            string
	serviceIPs         string
	serviceNames       string
	subdomain          string
)

func main() {
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&issuerName, "issuer-name", "", "The Cert-Manager Issuer name")
	flag.StringVar(&issuerKind, "issuer-kind", "", "The Cert-Manager Issuer name")
	flag.StringVar(&secretName, "secret-name", "", "The Cert-Manager Issuer name")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&podName, "pod-name", "", "name as defined by pod.metadata.name")
	flag.StringVar(&podIP, "pod-ip", "", "IP address as defined by pod.status.podIP")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&serviceIPs, "service-ips", "", "service IP addresses that resolve to this Pod; comma separated")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.Parse()

	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("unable to get Kube Cluster Config : %s", err)
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to connect to Kube Cluster : %s", err)
	}

    cmClientSet, err := cmclientset.NewForConfig(config)
    if err != nil {
		log.Fatalf("unable to connect to Kube Cluster : %s", err)
    }

	// Gather the list of IP addresses for the certificate's IP SANs field which
	// include:
	//   - the pod IP address
	//   - 127.0.0.1 for localhost access
	//   - each service IP address that maps to this pod
	ip := net.ParseIP(podIP)
	if ip.To4() == nil && ip.To16() == nil {
		log.Fatal("invalid pod IP address")
	}

	ipaddresses := []string{podIP, "127.0.0.1"}

	for _, s := range strings.Split(serviceIPs, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip.To4() == nil && ip.To16() == nil {
			log.Fatal("invalid service IP address")
		}
		ipaddresses = append(ipaddresses, s)
	}

	// Gather a list of DNS names that resolve to this pod which include the
	// default DNS name:
	//   - ${pod-ip-address}.${namespace}.pod.${cluster-domain}
	//
	// For each service that maps to this pod a dns name will be added using
	// the following template:
	//   - ${service-name}.${namespace}.svc.${cluster-domain}
	//
	// A dns name will be added for each additional DNS name provided via the
	// `-additional-dnsnames` flag.
	dnsNames := defaultDNSNames(podIP, hostname, subdomain, namespace, clusterDomain)

	for _, n := range strings.Split(additionalDNSNames, ",") {
		if n == "" {
			continue
		}
		dnsNames = append(dnsNames, n)
	}

	for _, n := range strings.Split(serviceNames, ",") {
		if n == "" {
			continue
		}
		dnsNames = append(dnsNames, serviceDomainName(n, namespace, clusterDomain))
	}

	certificate := &cmv1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
		},
		Spec: cmv1alpha1.CertificateSpec{
			CommonName: dnsNames[0],
			SecretName: secretName,
			DNSNames: dnsNames,
			IPAddresses: ipaddresses,
			KeyAlgorithm: cmv1alpha1.RSAKeyAlgorithm,
			KeySize: 2048,			
			IssuerRef: cmv1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}

	cmClientSet.CertmanagerV1alpha1().Certificates(certificate.Namespace).Delete(certificate.Name, &metav1.DeleteOptions{})
	_, err2 := cmClientSet.CertmanagerV1alpha1().Certificates(certificate.Namespace).Create(certificate)
	if err2 != nil {
		log.Fatalf("unable to create the certificate : %s", err2)
	}
	log.Printf("Successfully created Certificate %s", secretName)


	log.Println("waiting for secret...")
	for {
		_, err := clientset.CoreV1().Secrets(namespace).Get(certificate.Name, metav1.GetOptions{})
		if err != nil {
			log.Printf("unable to retrieve certificate secret (%s): %s", certificate.Name, err)
			time.Sleep(5 * time.Second)
			continue
		}

		break

	}
	log.Printf("Successfully rerieved certificate secret %s", secretName)
	
	updateSecret(clientset, certificate, namespace)
	
	os.Exit(0)
}

func defaultDNSNames(ip, hostname, subdomain, namespace, clusterDomain string) []string {
	ns := []string{podDomainName(ip, namespace, clusterDomain)}
	if hostname != "" && subdomain != "" {
		ns = append(ns, podHeadlessDomainName(hostname, subdomain, namespace, clusterDomain))
	}
	return ns
}

func serviceDomainName(name, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}

func podDomainName(ip, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.pod.%s", strings.Replace(ip, ".", "-", -1), namespace, domain)
}

func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}

func updateSecret(clientset *kubernetes.Clientset, crt *cmv1alpha1.Certificate, namespace string) (*v1.Secret, error) {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(crt.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	
	key, err := x509.ParsePKCS1PrivateKey(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		return nil, err
	}

	pkcs8Key,err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
		
	keyStore := keystore.KeyStore{
		"secretName": &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			PrivKey: pkcs8Key,
			CertChain: []keystore.Certificate{
				keystore.Certificate{
					Type: "X509",
					Content: secret.Data[v1.TLSCertKey],	
				},
			},
		},
	}

	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	defer zeroing(password)
	var b bytes.Buffer
    writer := bufio.NewWriter(&b)
    err = keystore.Encode(writer, keyStore, password)
	if err != nil {
		return nil, err
	}
	writer.Flush()
	secret.Data["keystore.jks"] = b.Bytes()

	secret, err = clientset.CoreV1().Secrets(namespace).Update(secret)
	
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}
