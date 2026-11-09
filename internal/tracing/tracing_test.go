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

package tracing

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests below share opentracing's global tracer, so they do not run in parallel.

func useMockTracer(t *testing.T) *mocktracer.MockTracer {
	t.Helper()

	previous := opentracing.GlobalTracer()
	tracer := mocktracer.New()
	opentracing.SetGlobalTracer(tracer)
	t.Cleanup(func() { opentracing.SetGlobalTracer(previous) })

	return tracer
}

func TestNilSpanHelpersAreNoOps(t *testing.T) { //nolint:paralleltest // shares opentracing's global tracer
	span, ctx := StartSpanFromContext(nil, "op") //nolint:staticcheck // nil context is the documented no-op case
	assert.Nil(t, span)
	assert.Nil(t, ctx)

	assert.Nil(t, StartChildSpan(nil, "child"))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid", nil)
	require.NoError(t, err)
	assert.NoError(t, InjectSpanIntoRequest(nil, req))
	assert.Empty(t, req.Header)

	assert.NotPanics(t, func() {
		Finish(nil)
		AddLog(nil, "k", "v")
		AddTag(nil, "k", "v")
		TraceError(nil, errors.New("boom"))
	})
}

// With no tracer registered, opentracing falls back to its no-op tracer. This is
// how the SDK runs in any application that doesn't call opentracing.SetGlobalTracer.
func TestHelpersWithDefaultNoopTracer(t *testing.T) { //nolint:paralleltest // shares opentracing's global tracer
	previous := opentracing.GlobalTracer()
	opentracing.SetGlobalTracer(opentracing.NoopTracer{})
	t.Cleanup(func() { opentracing.SetGlobalTracer(previous) })

	root, ctx := StartSpanFromContext(context.Background(), "root")
	require.NotNil(t, root)
	require.NotNil(t, ctx)

	child := StartChildSpan(root, "child")
	require.NotNil(t, child)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid", nil)
	require.NoError(t, err)
	assert.NoError(t, InjectSpanIntoRequest(child, req))
	assert.Empty(t, req.Header, "the no-op tracer adds no headers")

	assert.NotPanics(t, func() {
		AddLog(child, "k", "v")
		TraceError(child, errors.New("boom"))
		Finish(child)
		Finish(root)
	})
}

func TestSpansAreRecordedWithParentAndError(t *testing.T) { //nolint:paralleltest // shares opentracing's global tracer
	tracer := useMockTracer(t)

	root, ctx := StartSpanFromContext(context.Background(), "root")
	require.NotNil(t, root)
	assert.NotNil(t, opentracing.SpanFromContext(ctx))

	child := StartChildSpan(root, "child")
	require.NotNil(t, child)

	AddLog(child, "key", "value")
	TraceError(child, errors.New("boom"))
	TraceError(child, nil)
	Finish(child)
	Finish(root)

	finished := tracer.FinishedSpans()
	require.Len(t, finished, 2)

	gotChild, gotRoot := finished[0], finished[1]
	assert.Equal(t, "child", gotChild.OperationName)
	assert.Equal(t, "root", gotRoot.OperationName)
	assert.Equal(t, gotRoot.SpanContext.SpanID, gotChild.ParentID)
	assert.Equal(t, true, gotChild.Tag("error"))

	logs := gotChild.Logs()
	require.Len(t, logs, 2)
	assert.Equal(t, "value", logs[0].Fields[0].ValueString)
	assert.Equal(t, "boom", logs[1].Fields[0].ValueString)
}

func TestInjectSpanIntoRequestWritesHeaders(t *testing.T) { //nolint:paralleltest // shares opentracing's global tracer
	useMockTracer(t)

	span, _ := StartSpanFromContext(context.Background(), "outgoing")
	require.NotNil(t, span)
	defer Finish(span)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid", nil)
	require.NoError(t, err)
	require.NoError(t, InjectSpanIntoRequest(span, req))
	assert.NotEmpty(t, req.Header)
}
