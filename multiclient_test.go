package iam

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/AccelByte/go-jose"
	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/stretchr/testify/assert"
)

var (
	testMultiClient *MultiClient
	issuers         []string
	multiSigner     []jose.Signer
	privateKeys     []*rsa.PrivateKey
)

const (
	testMultiJWTPrivateKey0 = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgH7PvaMr0eWKQTU1C7qlM8oJRW1+zkfs/9nBs6SyxxWihuaYTsWv
i1hChNT5nZOgG3mj/g9ncoPp/OWnacJ6q4igeEGyEi1ObpuJiufO7q9xTq9nEv/+
5URiKepBv4/HbTCCfLPMVe/b0fid+qFetNfE0RdGcskav7lf62fPjf73AgMBAAEC
gYAngJEDRkAxL7sWVvrbXmDem7q73BdoAmTEsXlDYclwbNt285T+MavHh5kXOtai
SOqmHrail8ftXbNA2sCwK0RJar7WitGw/gF/M7ieT71wyiGzxirZsWkgkMK6Mb5n
+BEaI6oliRJhblFJ6Ws7QtifbYFdSm2q4oF8OtOlwagXsQJBAPPKwpqKdVIj57/L
VTwC/DDYR1l04ezq6bv7hz52+UWQuhL80PY/nFehGAogZDs5vuQgZsVq+YPLBjF5
sF3mQA8CQQCFKV+fDq/Z2fRQrcc2JE+NoFQEJ6FySS34o6WhgNHqN2x7W857P/1b
9Eg1yid+ci2N4UVt5TJ2vImYdQt7XOqZAkA4rTa4vt+vjPFfwWG7ZeZDZMSRo36y
mZplPYCfoQEqjw7zQxtBZGBwbt8r24Px0Ob0GiRKWShQ3249KlE6Q0E5AkB1zYZU
dm/HsHPdM/96vGDMkDwDePPw4SCUSGHtIMOUCvgjobJngtKnGNMREwghau02CUac
1BjyxhSMFW/U8PxxAkEA1ybx9eXfLXpa2Rw5kK3xF/H0QAoMBqPJttLDYyxu/YhQ
0kmcadY0Ls+sw0u1funmuzO2PhS2Q/GxHGau6hr3yg==
-----END RSA PRIVATE KEY-----`
	testMultiJWTPrivateKey1 = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDfmTDksBef00FbqZ2EWdOPaNmXZeNwDW/xZ95U1wOq6otJSnYs
is7xYbrPCObgbZ+rUECDBoLc/pOUgDKQCimtk5XW2tSy55D2+YwCfWepZFLTxlag
sHAhfx9FGjbt6PdUx8x4iMDN4AXV4VRZDGBQH5/Z/Gq/XhehZAmcYcUwvQIDAQAB
AoGBAKHJenM+ZxmiBhyI8gyd4lJWD3tYoeSmFGWcPmcs3N6Crx3s3u0D0xEdIcpE
KqohJ/MRMlycDXxSR/6fc/Z9JAG1rAemT1BkCElPTDq8SDExhFGBOtVobD9ByIoY
70jOTHRtKscZhfJAu3f25MmLjWqMvMoBsOW7OPsY0kKk0bEBAkEA+2oVwIqHm2Vl
aozpiwKSWrKKe0sUM9Mkm0G2oic3nA035fzgzB0jCVLh9rwlx+NWIeSqjPK/NeWL
wQu2MPXx0QJBAOOtOfQCOVvjHNJ96NqJ/JNNkF+Dv/Mtq9B0DC7OYUwAMGUAF407
+Q9q+bDedzOFTPHWGTkfNUc7yhcYyXQjfy0CQQDhrVxRNQh9CQt8FXkd+vT8zP9Z
pQ9BZeqaIuaZr7JPNd5TaCcxkYX9vJRxMnqHbx3F1sjxNIVHEAHfC3BDisHBAkEA
kn4LI+2qam0fRnCtOrA+S6lEk7B5+UYRnvaMQDGaeQRGHzaH8N/9yOXT8vGxUP0c
HR7c69wgs8zMoz/Xn1qXoQJAK6V9yvv9FeNi7Mvr27e+hdFG8JBHl35P2RYaKQUU
RFT4Jtk/maqrDJ0WqGL46UFw9nEaTUyqoycjg5aNkPDN2w==
-----END RSA PRIVATE KEY-----`
)

func init() {
	jaeger.InitGlobalTracer(jaegerAgentHost, "", "multiclient test", "")

	issuers = []string{"issuer1", "issuer2"}
	jwtPrivateKeys := []string{testMultiJWTPrivateKey0, testMultiJWTPrivateKey1}

	testMultiClient = NewMultiClient(&MultiClientConfig{})
	testMultiClient.keys = map[string]map[string]*rsa.PublicKey{}
	testMultiClient.localValidationActive = true

	multiSigner = make([]jose.Signer, len(issuers))
	privateKeys = make([]*rsa.PrivateKey, len(issuers))

	for i, issuer := range issuers {
		privateKeys[i] = mustUnmarshalRSA(jwtPrivateKeys[i])
		testMultiClient.keys[issuer] = map[string]*rsa.PublicKey{}
		testMultiClient.keys[issuer][keyID] = &rsa.PublicKey{
			E: privateKeys[i].PublicKey.E,
			N: privateKeys[i].PublicKey.N,
		}
		signer, err := jose.NewSigner(
			jose.SigningKey{
				Algorithm: jose.RS256,
				Key: jose.JSONWebKey{
					KeyID: keyID,
					Key:   privateKeys[i],
				},
			},
			(&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			panic(err)
		}

		multiSigner[i] = signer
		testMultiClient.jwksNextRefresh.Store(issuer, time.Now())
	}
}

func Test_MultiStartLocalValidation(t *testing.T) {
	t.Parallel()

	called := map[string]bool{}
	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			resp := struct {
				Keys
				RevocationList
			}{}
			urlStr := req.URL.String()
			urlStr = urlStr[0:strings.Index(urlStr, "/")]
			called[urlStr] = true
			b, _ := json.Marshal(resp)

			r := ioutil.NopCloser(bytes.NewReader(b))

			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	conf := &MultiClientConfig{}
	multiClient := NewMultiClient(conf)
	multiClient.httpClient = mockHTTPClient
	for _, issuer := range issuers {
		multiClient.jwksNextRefresh.Store(issuer, time.Now().Add(-time.Minute))
	}

	err := multiClient.StartLocalValidation()
	assert.NoError(t, err, "start local validation should be successful")
	assert.True(t, multiClient.localValidationActive, "local validation should be active")

	time.Sleep(1 * time.Second) // wait request done
	counter := 0
	for _, issuer := range issuers {
		for k, _ := range called {
			if k == issuer {
				counter++
			}
		}
	}
	assert.Equal(t, len(issuers), counter)
}

func Test_MultiClientValidateAccessToken(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a"}
	claims := []*JWTClaims{}
	for _, issuer := range issuers {
		claim := generateClaims(t, userData)
		claim.Issuer = issuer
		claims = append(claims, claim)
	}

	for i, claim := range claims {
		accessToken, err := jwt.Signed(multiSigner[i]).Claims(claim).CompactSerialize()
		if err != nil {
			panic(err)
		}

		validationResult, _ := testMultiClient.ValidateAccessToken(accessToken)
		assert.True(t, validationResult, "valid direct verification should be granted")

		// test tracing
		validationResult, _ = testMultiClient.ValidateAccessToken(accessToken, WithJaegerContext(context.Background()))
		assert.True(t, validationResult, "valid direct verification should be granted")
	}
}

func Test_MultiClientValidateAccessToken_ExpiredToken(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a"}
	claims := []*JWTClaims{}
	for _, issuer := range issuers {
		claim := generateClaims(t, userData)
		claim.Issuer = issuer
		claim.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute))
		claims = append(claims, claim)
	}

	for i, claim := range claims {
		accessToken, err := jwt.Signed(multiSigner[i]).Claims(claim).CompactSerialize()
		if err != nil {
			panic(err)
		}

		validationResult, _ := testMultiClient.ValidateAccessToken(accessToken)
		assert.False(t, validationResult, "validate should be false")

		// test tracing
		validationResult, _ = testMultiClient.ValidateAccessToken(accessToken, WithJaegerContext(context.Background()))
		assert.False(t, validationResult, "validate should be false")
	}
}
