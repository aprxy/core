package httpproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/google/easypki/pkg/easypki"

	"github.com/google/easypki/pkg/store"
	"github.com/pkg/errors"
)

type Proxy struct {
	listenParam      string
	pki              *easypki.EasyPKI
	proxyHandlerFunc http.HandlerFunc
}

func NewProxy(ip, port string, proxyFunc http.HandlerFunc) (*Proxy, error) {
	u, err := user.Current()
	if err != nil {
		return nil, errors.Wrap(err, "could not get the current user")
	}

	return NewProxyWithCustomCertStorePath(ip, port, fmt.Sprintf("%s/.vamproxy", u.HomeDir), nil)
}

func NewProxyWithCustomCertStorePath(ip, port, certStorePath string, proxyFunc http.HandlerFunc) (*Proxy, error) {
	if err := os.Mkdir(certStorePath, os.ModePerm); err != nil {
		if os.IsExist(err) {
			log.Printf("%s already exists\n", certStorePath)
		} else {
			return nil, err
		}
	}

	listenParam := strings.Join([]string{ip, port}, ":")

	proxy := &Proxy{
		listenParam: listenParam,
		pki:         &easypki.EasyPKI{Store: &store.Local{Root: certStorePath}},
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

// Start starts the proxy using the given configuration in the NewProxy method
func (proxy *Proxy) Start() {
	log.Printf("proxy starting at %s using\n", proxy.listenParam)

	log.Fatalln(http.ListenAndServe(proxy.listenParam, proxy.proxyHandlerFunc))
}

func (proxy *Proxy) onTheFlyGenerateCertificate(host string) (*tls.Config, error) {
	caBundle, err := proxy.pki.GetCA(caName)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get the CA %s", caName)
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
			return nil, errors.Wrapf(err, "could not sign the certificate for %s", cliRequest.Name)
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
	}, nil
}

func defaultProxyFunc(proxy *Proxy, reverseProxy *httputil.ReverseProxy) http.HandlerFunc {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		originalReqBytes, err := httputil.DumpRequest(req, true)

		if err != nil {
			log.Fatalln(err)
		}

		log.Println(string(originalReqBytes))

		if req.Method == http.MethodConnect {
			proxy.handleHttpsProxy(req, rw)
		} else {
			reverseProxy.ServeHTTP(rw, req)
		}
	})
}

const RAW_HTTP_1_0_200 string = "HTTP/1.0 200 OK\r\n\r\n"
const RAW_HTTP_1_0_502 string = "HTTP/1.0 502 Bad Gateway\r\n\r\n"
const RAW_HTTP_1_0_500 string = "HTTP/1.0 500 Internal Proxy Error\r\n\r\n"
const VAMPROXY_ERROR string = `
<html>
<title>Vamproxy error</title>
<body>
	<h2>Error {{.StatusCode}} while executing the below request:</h2><br><br>
	{{if .ReadReqError}}
	{{.ReadReqError}}
	{{else}}
	{{.ReqBody}}
	{{end}}
	<br><br>
	<h2>Stacktrace:<h2><br><br>
	{{.StackTrace}}
</body>
</html>
`

func handleProxyError(req *http.Request, writer io.Writer, httpStatus uint, httpHead string, givenError error) error {
	tpl, err := template.New("errorTemplate").Parse(VAMPROXY_ERROR)

	// if an error happens here, then it means that the template is broken (which should never happen)
	if err != nil {
		panic(err)
	}

	reqBytes, err := httputil.DumpRequest(req, true)
	data := make(map[string]interface{})
	data["StatusCode"] = httpStatus
	if err != nil {
		data["ReadReqError"] = err.Error()
	} else {
		data["ReqDump"] = string(reqBytes)
	}

	data["StackTrace"] = fmt.Sprintf("%+v", givenError)

	_, err = fmt.Fprint(writer, httpHead)
	if err != nil {
		return errors.Wrap(err, "error while writing http head")
	}

	err = tpl.Execute(writer, data)
	if err != nil {
		panic(err)
	}

	return givenError
}

func (proxy *Proxy) handleHttpsProxy(req *http.Request, rw http.ResponseWriter) error {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return handleProxyError(req, rw, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.New("response writer doesn't implement http.Hijacker"))
	}

	clientConnection, _, err := hijacker.Hijack()
	if err != nil {
		return handleProxyError(req, rw, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "could not hijack the client connection"))
	}

	_, err = fmt.Fprint(clientConnection, RAW_HTTP_1_0_200)
	if err != nil {
		return handleProxyError(req, clientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "error while writing the http header"))
	}

	cfg, err := proxy.onTheFlyGenerateCertificate(req.Host)
	if err != nil {
		return handleProxyError(req, clientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrapf(err, "error while getting the certificate for %s", req.Host))
	}

	tlsClientConnection := tls.Server(clientConnection, cfg)

	if err := tlsClientConnection.Handshake(); err != nil {
		return handleProxyError(req, clientConnection, http.StatusInsufficientStorage, RAW_HTTP_1_0_500, errors.Wrap(err, "error while doing TLS handshake"))
	}

	trans, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("cannot type assert http.DefaultTransport to http.Transport")
	}

	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	clientReader := bufio.NewReader(tlsClientConnection)

	log.Printf("connecting to %s\n", req.URL.Host)
	targetConnection, err := trans.DialContext(req.Context(), "tcp", req.URL.Host)

	if err != nil {
		return handleProxyError(req, tlsClientConnection, http.StatusBadGateway, RAW_HTTP_1_0_502, errors.Wrapf(err, "error while connecting to the target host %s: %v", req.URL.Host, err))
	}

	log.Println("handling tls connection")

	defer func() {
		log.Println("closing both connections")
		tlsClientConnection.Close()
		targetConnection.Close()
	}()

	for !isEof(clientReader) {
		log.Println("trying to read the request from the client")

		realReq, err := http.ReadRequest(clientReader)

		if err != nil {
			if err != io.EOF {
				return handleProxyError(req, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "error while reading the client request"))
			}
			break
		}

		realReq.URL.Scheme = "https"
		realReq.URL.Host = req.URL.Hostname()
		realReq.RemoteAddr = req.RemoteAddr

		bytesReq, err := httputil.DumpRequest(realReq, true)
		if err != nil {
			log.Printf("could not dump the request: %+v", err)
		}

		log.Printf("Printing request:\n%s\n", string(bytesReq))

		removeProxyHeaders(realReq)

		targetResponse, err := trans.RoundTrip(realReq)

		if err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusBadGateway, RAW_HTTP_1_0_502, errors.Wrap(err, "error while executing round trip"))
		}

		if _, err := fmt.Fprintf(tlsClientConnection, "HTTP/%d.%d %s\r\n", 1, 1, targetResponse.Status); err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "error while writing http head"))
		}

		targetResponse.Header.Set("Connection", "close")
		targetResponse.Header.Set("Transfer-Encoding", "chunked")

		if err = targetResponse.Header.Write(tlsClientConnection); err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "error while writing headers to the client"))
		}

		tlsClientConnection.Write([]byte("\r\n"))

		chunkedWriter := newChunkedWriter(tlsClientConnection)

		if _, err := io.Copy(chunkedWriter, targetResponse.Body); err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "erorr while writing body to the client"))
		}

		if err := chunkedWriter.Close(); err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "error while closing chunked writer"))
		}

		if _, err = io.WriteString(tlsClientConnection, "\r\n"); err != nil {
			return handleProxyError(realReq, tlsClientConnection, http.StatusInternalServerError, RAW_HTTP_1_0_500, errors.Wrap(err, "Cannot write TLS response chunked trailer from mitm'd client"))
		} else {
			log.Println("wrote final trailers")
		}
	}

	log.Println("broke the loop")

	return nil
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
	_, err := r.Peek(1)

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
