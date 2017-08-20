package httpproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/easypki/pkg/easypki"

	"github.com/google/easypki/pkg/store"
)

type Protocol string

const HTTP_PROTOCOL Protocol = "http://"
const HTTPS_PROTOCOL Protocol = "https://"

type Proxy struct {
	protocol         Protocol
	listenParam      string
	url              *url.URL
	proxyHandlerFunc http.HandlerFunc
	pki              *easypki.EasyPKI
}

func NewProxy(protocol Protocol, ip, port string, proxyFunc http.HandlerFunc) (*Proxy, error) {
	url, err := url.Parse(fmt.Sprintf("%s%s:%s", protocol, ip, port))

	if err != nil {
		return nil, err
	}

	listenParam := strings.Join([]string{ip, port}, ":")

	if proxyFunc == nil {
		reverseProxy := newReverseProxy()
		proxyFunc = http.HandlerFunc(defaultProxyFunc(reverseProxy))
	}

	proxy := &Proxy{
		protocol, listenParam, url, proxyFunc, &easypki.EasyPKI{Store: &store.Local{Root: "/home/renannp/development/go/src/github.com/vamproxy/cli/certs"}},
	}

	generateCertificate(proxy)

	return proxy, nil
}

func generateCertificate(proxy *Proxy) {
	// priv, err := rsa.GenerateKey(rand.Reader, 2048)

	// if err != nil {
	// 	panic(err)
	// }

	commonSubject := pkix.Name{
		Organization:       []string{"Vamproxy Inc."},
		OrganizationalUnit: []string{"IT"},
		Locality:           []string{"Your Desk"},
		Country:            []string{"ZU"},
		Province:           []string{"Your Mom"},
	}

	caRequest := &easypki.Request{
		Name: "Root_CA",
		Template: &x509.Certificate{
			Subject:    commonSubject,
			NotAfter:   time.Now().AddDate(100, 0, 0),
			MaxPathLen: 1,
			IsCA:       true,
		},
	}
	caRequest.Template.Subject.CommonName = "Root CA"
	if err := proxy.pki.Sign(nil, caRequest); err != nil {
		log.Fatalf("Sign(nil, %v): got error: %v != expected nil", caRequest, err)
	}
	_, err := proxy.pki.GetCA(caRequest.Name)
	if err != nil {
		log.Fatalf("GetCA(%v): got error %v != expect nil", caRequest.Name, err)
	}

	// cliRequest := &Request{
	// 	Name: "seila@seila.org",
	// 	Template: &x509.Certificate{
	// 		Subject:        commonSubject,
	// 		NotAfter:       time.Now().AddDate(0, 0, 30),
	// 		EmailAddresses: []string{"bob@acme.org"},
	// 	},
	// 	IsClientCertificate: true,
	// }
	// cliRequest.Template.Subject.CommonName = "bob@acme.org"
	// if err := pki.Sign(rootCA, cliRequest); err != nil {
	// }

}

func (p *Proxy) Start() {

	log.Printf("proxy starting at %s using %s protocol\n", p.listenParam, p.protocol)

	switch p.protocol {
	case HTTP_PROTOCOL:
		{
			// go func() {
			log.Fatalln(http.ListenAndServe(p.listenParam, p.proxyHandlerFunc))
			// }()
		}
	case HTTPS_PROTOCOL:
		{
			// go func() {
			log.Fatalln(http.ListenAndServeTLS(p.listenParam, "cert.pem", "key.pem", p.proxyHandlerFunc))
			// }()
		}
	}
}

func defaultProxyFunc(reverseProxy *httputil.ReverseProxy) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		bytes, err := httputil.DumpRequest(req, true)

		if err != nil {
			log.Fatalln(err)
		}

		log.Println(string(bytes))

		if req.Method == http.MethodConnect {
			hijacker, ok := rw.(http.Hijacker)
			if !ok {
				rw.Write([]byte("error"))
				rw.WriteHeader(http.StatusInternalServerError)
			}

			clientConnection, _, err := hijacker.Hijack()
			if err != nil {
				rw.Write([]byte("error"))
				rw.WriteHeader(http.StatusInternalServerError)
			}

			clientConnection.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

			// tls.Server(clientConnection)

			trans, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				panic("not ok")
			}

			targetConnection, err := trans.DialContext(req.Context(), "tcp", req.URL.Host)

			if err != nil {
				panic(err)
			}

			clientReader, targetReader := bufio.NewReader(clientConnection), bufio.NewReader(targetConnection)

			req, err := http.ReadRequest(clientReader)

			if err != nil {
				panic(err)
			}

			err = req.Write(targetConnection)

			if err != nil {
				panic(err)
			}

			resp, err := http.ReadResponse(targetReader, req)

			if err != nil {
				panic(err)
			}

			if err = resp.Write(clientConnection); err != nil {
				panic(err)
			}

			// works
			// wg := &sync.WaitGroup{}
			// wg.Add(2)
			// go func() {
			// 	if _, err := io.Copy(proxyConn, clientConn); err != nil {
			// 		log.Printf("%+v\n", err)
			// 	}
			// 	wg.Done()
			// }()

			// go func() {
			// 	if _, err := io.Copy(clientConn, proxyConn); err != nil {
			// 		log.Printf("%+v\n", err)
			// 	}

			// 	wg.Done()
			// }()

			// wg.Wait()
			// works

			log.Println("closing both connections")

			clientConnection.Close()
			targetConnection.Close()
		} else {
			reverseProxy.ServeHTTP(rw, req)
		}

		// if req.URL.Port() == "443" && req.Method == http.MethodConnect {
		if false {
			// goproxy.NewProxyHttpServer().ServeHTTP
		}
		// }
	})
}

func newReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// if req.URL.Port() == "443" && req.Method == http.MethodConnect {
			// req.URL.Scheme = "http"
			// }
		},
	}
}

func newHttpsReverseProxy() *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "https",
		Host:   "golang.org",
	})

	transport := &http.Transport{}
	// transport.Proxy = func(req *http.Request) (*url.URL, error) {

	// }

	proxy.Transport = transport

	return proxy
}

func dialTLS(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{ServerName: host}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	cert := cs.PeerCertificates[0]

	// Verify here
	cert.VerifyHostname(host)
	log.Println(cert.Subject)

	return tlsConn, nil
}
