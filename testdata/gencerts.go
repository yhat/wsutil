package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"
)

type CertInfo struct {
	IsCA        bool
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	IPAddresses []net.IP
}

// Generate a new certificate. If the certificate is self signed, parent and
// parentKey should be nil.
func NewCert(parent *x509.Certificate, parentKey *rsa.PrivateKey, info CertInfo) (cert, key []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.New("failed to generate key pair: " + err.Error())
	}

	// this certs will be used forever
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 876581)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Yhat, Inc."}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              info.KeyUsage,
		ExtKeyUsage:           info.ExtKeyUsage,
		IsCA:                  info.IsCA,
		IPAddresses:           info.IPAddresses,
		BasicConstraintsValid: true,
	}

	pub := priv.Public()
	var p *x509.Certificate
	var signingKey *rsa.PrivateKey
	if parent == nil {
		p = &tmpl
		signingKey = priv
	} else {
		p = parent
		signingKey = parentKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, p, pub, signingKey)
	if err != nil {
		return nil, nil, errors.New("failed to create certificate: " + err.Error())
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	keyPEM := pem.EncodeToMemory(block)

	return certPEM, keyPEM, nil
}

func DecodeKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no private key found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func DecodeCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no cert found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func genCerts() error {
	// create a root certificate
	rootInfo := CertInfo{
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	}

	rootCertPEM, rootKeyPEM, err := NewCert(nil, nil, rootInfo)
	if err != nil {
		return fmt.Errorf("failed to create cert: ", err)
	}

	rootKey, err := DecodeKey(rootKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse private key: ", err)
	}
	rootCert, err := DecodeCert(rootCertPEM)
	if err != nil {
		return fmt.Errorf("failed to parse root cert: ", err)
	}

	// create the server certificate
	serverInfo := CertInfo{
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverCertPEM, serverKeyPEM, err := NewCert(rootCert, rootKey, serverInfo)
	if err != nil {
		return fmt.Errorf("failed to create cert: ", err)
	}

	certs := []struct {
		Name string
		Data []byte
	}{
		{"root_cert.crt", rootCertPEM},
		{"root_key.crt", rootKeyPEM},
		{"server_cert.crt", serverCertPEM},
		{"server_key.crt", serverKeyPEM},
	}
	for _, cert := range certs {
		err = ioutil.WriteFile(cert.Name, cert.Data, 0600)
		if err != nil {
			return fmt.Errorf("error creating file %s %v", cert.Name, err)
		}
	}

	return nil
}

func main() {
	if err := genCerts(); err != nil {
		log.Fatal(err)
	}
}
