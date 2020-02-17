module github.com/AccelByte/iam-go-sdk

go 1.12

require (
	github.com/AccelByte/bloom v0.0.0-20180915202807-98c052463922
	github.com/AccelByte/go-jose v2.1.4+incompatible
	github.com/AccelByte/go-restful-plugins/v3 v3.1.2
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorhill/cronexpr v0.0.0-20180427100037-88b0669f7d75
	github.com/opentracing/opentracing-go v1.1.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.1
	github.com/stretchr/testify v1.4.0
)

replace github.com/AccelByte/go-restful-plugins/v3 v3.1.2 => ./tmp/go-restful-plugins
