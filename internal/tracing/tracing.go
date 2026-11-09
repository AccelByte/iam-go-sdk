// Copyright 2026 AccelByte Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tracing holds the opentracing span helpers used by the SDK.
//
// They were previously imported from go-restful-plugins/v3/pkg/jaeger, which
// also pulled in its Jaeger client and HTTP framework dependencies. The
// behaviour is unchanged: spans are created through opentracing's global
// tracer, so they are recorded only if the application registers one.
package tracing

import (
	"context"
	"net/http"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
)

// StartSpanFromContext starts a span as a child of the span in ctx.
// It returns a nil span when ctx is nil.
func StartSpanFromContext(ctx context.Context, operationName string) (opentracing.Span, context.Context) {
	if ctx != nil {
		return opentracing.StartSpanFromContext(ctx, operationName)
	}

	return nil, ctx
}

// StartChildSpan starts a span as a child of span. It returns nil when span is nil.
func StartChildSpan(span opentracing.Span, name string) opentracing.Span {
	if span != nil {
		return opentracing.StartSpan(name, opentracing.ChildOf(span.Context()))
	}

	return nil
}

// InjectSpanIntoRequest writes the span context into the request headers.
func InjectSpanIntoRequest(span opentracing.Span, req *http.Request) error {
	if span != nil {
		return opentracing.GlobalTracer().Inject(
			span.Context(),
			opentracing.HTTPHeaders,
			opentracing.HTTPHeadersCarrier(req.Header))
	}

	return nil
}

// Finish finishes span if it is not nil.
func Finish(span opentracing.Span) {
	if span != nil {
		span.Finish()
	}
}

// AddLog adds a key/value log field to span if it is not nil.
func AddLog(span opentracing.Span, key string, value string) {
	if span != nil {
		span.LogFields(log.String(key, value))
	}
}

// AddTag sets a tag on span if it is not nil.
func AddTag(span opentracing.Span, key string, value string) {
	if span != nil {
		span.SetTag(key, value)
	}
}

// TraceError records err on span as an error log field and sets the standard
// boolean error tag.
func TraceError(span opentracing.Span, err error) {
	if err != nil && span != nil {
		AddLog(span, "error", err.Error())
		ext.Error.Set(span, true)
	}
}
