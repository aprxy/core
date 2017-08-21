package httpproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
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
	pki              *easypki.EasyPKI
	proxyHandlerFunc http.HandlerFunc
}

func NewProxy(protocol Protocol, ip, port string, proxyFunc http.HandlerFunc) (*Proxy, error) {
	url, err := url.Parse(fmt.Sprintf("%s%s:%s", protocol, ip, port))

	if err != nil {
		return nil, err
	}

	listenParam := strings.Join([]string{ip, port}, ":")

	proxy := &Proxy{
		protocol:    protocol,
		listenParam: listenParam,
		url:         url,
		pki:         &easypki.EasyPKI{Store: &store.Local{Root: "/home/renannp/development/go/src/github.com/vamproxy/cli/certs"}},
	}

	if proxyFunc == nil {
		reverseProxy := newReverseProxy()
		proxyFunc = http.HandlerFunc(defaultProxyFunc(proxy, reverseProxy))
	}

	proxy.proxyHandlerFunc = proxyFunc

	generateCertificate(proxy)

	return proxy, nil
}

var commonSubject = pkix.Name{
	Organization:       []string{"Vamproxy Inc."},
	OrganizationalUnit: []string{"IT"},
	Locality:           []string{"Your Desk"},
	Country:            []string{"ZU"},
	Province:           []string{"Your Mom"},
}

const caName = "Root_CA"

func generateCertificate(proxy *Proxy) {
	caRequest := &easypki.Request{
		Name: caName,
		Template: &x509.Certificate{
			Subject:    commonSubject,
			NotAfter:   time.Now().AddDate(100, 0, 0),
			MaxPathLen: 1,
			IsCA:       true,
		},
	}
	caRequest.Template.Subject.CommonName = "Root CA"
	if err := proxy.pki.Sign(nil, caRequest); err != nil {
		log.Printf("Sign(nil, %v): got error: %v != expected nil", caRequest, err)
	}
}

func (proxy *Proxy) Start() {

	log.Printf("proxy starting at %s using %s protocol\n", proxy.listenParam, proxy.protocol)

	switch proxy.protocol {
	case HTTP_PROTOCOL:
		{
			// go func() {
			log.Fatalln(http.ListenAndServe(proxy.listenParam, proxy.proxyHandlerFunc))
			// }()
		}
	case HTTPS_PROTOCOL:
		{
			// go func() {
			log.Fatalln(http.ListenAndServeTLS(proxy.listenParam, "cert.pem", "key.pem", proxy.proxyHandlerFunc))
			// }()
		}
	}
}

func (proxy *Proxy) onTheFlyGenerateCertificate(host string) *tls.Config {
	caBundle, err := proxy.pki.GetCA(caName)
	if err != nil {
		log.Fatalf("GetCA(%v): got error %v != expect nil", caName, err)
	}

	cliRequest := &easypki.Request{
		Name: host,
		Template: &x509.Certificate{
			Subject:               commonSubject,
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Now().AddDate(40, 0, 0),
			EmailAddresses:        []string{"bob@acme.org"},
			Issuer:                caBundle.Cert.Subject,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		IsClientCertificate: false,
	}

	if ip := net.ParseIP(host); ip != nil {
		cliRequest.Template.IPAddresses = append(cliRequest.Template.IPAddresses, ip)
	} else {
		cliRequest.Template.DNSNames = append(cliRequest.Template.DNSNames, host)
	}

	// get the new generated certificate
	hostBundle, err := proxy.pki.GetBundle(caName, host)
	if err != nil {
		if err := proxy.pki.Sign(caBundle, cliRequest); err != nil {
			log.Println(err)
			return nil
		}

		hostBundle, _ = proxy.pki.GetBundle(caName, host)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{hostBundle.Cert.Raw},
		PrivateKey:  hostBundle.Key,
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
}

func defaultProxyFunc(proxy *Proxy, reverseProxy *httputil.ReverseProxy) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		originalReqBytes, err := httputil.DumpRequest(req, true)

		if err != nil {
			log.Fatalln(err)
		}

		log.Println(string(originalReqBytes))

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

			cfg := proxy.onTheFlyGenerateCertificate(req.Host)
			if cfg == nil {
				clientConnection.Write([]byte("HTTP/1.0 500 OK\r\n\r\n"))
				clientConnection.Close()
				return
			}

			tlsClientConnection := tls.Server(clientConnection, cfg)

			if err := tlsClientConnection.Handshake(); err != nil {
				panic(err)
			}

			trans, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				panic("not ok")
			}

			trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

			clientReader := bufio.NewReader(tlsClientConnection)

			// targetConnection, err := trans.DialTLS(req.Context(), "tcp", req.URL.Host)
			log.Printf("connecting to %s\n", req.URL.Host)
			targetConnection, err := trans.DialContext(req.Context(), "tcp", req.URL.Host)

			if err != nil {
				log.Printf("error while connecting to the target host %s: %v", req.URL.Host, err)
				return
			}

			go func() {
				log.Println("handling tls connection")

				defer func() {
					log.Println("closing both connections")
					clientConnection.Close()
					targetConnection.Close()
				}()

				for !isEof(clientReader) {
					log.Println("trying to read the request from the client")

					realReq, err := http.ReadRequest(clientReader)

					if err != nil {
						if err != io.EOF {
							log.Printf("error while reading response: %v", err)
						}
						break
					}

					realReq.URL.Scheme = "https"
					realReq.URL.Host = req.URL.Hostname()

					bytesReq, _ := httputil.DumpRequest(realReq, true)
					if err != nil {
						panic(err)
					}
					log.Printf("Printing request: %s\n", string(bytesReq))

					if err != nil {
						panic(err)
					}

					realReq.RemoteAddr = req.RemoteAddr

					removeProxyHeaders(realReq)

					targetResponse, err := trans.RoundTrip(realReq)

					if err != nil {
						log.Fatalf("rountTrip: %v", err)
					}

					if _, err := fmt.Fprintf(tlsClientConnection, "HTTP/%d.%d %s\r\n", 1, 1, targetResponse.Status); err != nil {
						log.Fatalf("writing http status line: %v", err)
					}

					targetResponse.Header.Set("Connection", "close")
					targetResponse.Header.Set("Transfer-Encoding", "chunked")

					if err = targetResponse.Header.Write(tlsClientConnection); err != nil {
						log.Fatalf("writing headers: %v", err)
					}

					tlsClientConnection.Write([]byte("\r\n"))

					chunkedWriter := NewChunkedWriter(tlsClientConnection)

					if _, err := io.Copy(chunkedWriter, targetResponse.Body); err != nil {
						log.Fatalf("error while writing the body to the client: %v", err)
					}

					if err := chunkedWriter.Close(); err != nil {
						log.Fatalf("error while closing chunked writer: %v", err)
					}

					if _, err = io.WriteString(tlsClientConnection, "\r\n"); err != nil {
						log.Fatalf("Cannot write TLS response chunked trailer from mitm'd client: %v", err)
					} else {
						log.Println("wrote final trailers")
					}

					// respBytes, _ := httputil.DumpResponse(targetResponse, false)

					// targetResponse.Header.Set("Connection", "close")

					// log.Printf("\n\n\nPrinting target response: %s\n\n\n\n", string(respBytes))

					// if err = targetResponse.Write(tlsClientConnection); err != nil {
					// 	panic(err)
					// }
				}

				log.Println("broke the loop")
			}()

			/// NOT NEEDED YET
			// targetReader := bufio.NewReader(targetConnection)

			// err = realReq.Write(targetConnection)

			// resp, err := http.ReadResponse(targetReader, req)

			// if err != nil {
			// 	panic(err)
			// }
			/// NOT NEEDED YET

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

			// log.Println("closing both connections")

			// clientConnection.Close()
			// targetConnection.Close()
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

// from goproxy
func removeProxyHeaders(r *http.Request) {
	r.RequestURI = "" // this must be reset when serving a request with the client
	log.Printf("Sending request %v %v\n", r.Method, r.URL.String())
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
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

func isEof(r *bufio.Reader) bool {
	log.Println("before peek(1)")
	_, err := r.Peek(1)

	log.Printf("after peek(1): %v", err)

	if err == io.EOF {
		return true
	}
	return false
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
