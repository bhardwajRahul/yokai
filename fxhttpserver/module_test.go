package fxhttpserver_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ankorstore/yokai/fxconfig"
	"github.com/ankorstore/yokai/fxgenerate"
	"github.com/ankorstore/yokai/fxhttpserver"
	"github.com/ankorstore/yokai/fxhttpserver/testdata/errorhandler"
	"github.com/ankorstore/yokai/fxhttpserver/testdata/factory"
	"github.com/ankorstore/yokai/fxhttpserver/testdata/handler"
	"github.com/ankorstore/yokai/fxhttpserver/testdata/middleware"
	"github.com/ankorstore/yokai/fxhttpserver/testdata/service"
	"github.com/ankorstore/yokai/fxlog"
	"github.com/ankorstore/yokai/fxmetrics"
	"github.com/ankorstore/yokai/fxmetrics/testdata/spy"
	"github.com/ankorstore/yokai/fxtrace"
	"github.com/ankorstore/yokai/httpserver"
	"github.com/ankorstore/yokai/log"
	"github.com/ankorstore/yokai/log/logtest"
	"github.com/ankorstore/yokai/trace/tracetest"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

var (
	// request headers parts
	testRequestId   = "33084b3e-9b90-926c-af19-3859d70bd296"
	testTraceId     = "c4ca71e03e42c2c3d54293a6e2608bfa"
	testSpanId      = "8d0fdc8a74baaaea"
	testTraceParent = fmt.Sprintf("00-%s-%s-01", testTraceId, testSpanId)

	// resources
	concreteGlobalMiddleware = func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log.CtxLogger(c.Request().Context()).Info().Msg("CONCRETE GLOBAL middleware")

			return next(c)
		}
	}

	concreteGroupMiddleware = func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log.CtxLogger(c.Request().Context()).Info().Msg("CONCRETE GROUP middleware")

			return next(c)
		}
	}

	concreteHandlerMiddleware = func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log.CtxLogger(c.Request().Context()).Info().Msg("CONCRETE HANDLER middleware")

			return next(c)
		}
	}

	concreteHandler = func(c echo.Context) error {
		log.CtxLogger(c.Request().Context()).Info().Msg("in concrete handler")

		return c.JSON(http.StatusOK, "concrete")
	}

	panicHandler = func(c echo.Context) error {
		panic("test panic")
	}
)

//nolint:maintidx
func TestModuleWithAutowiredResources(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsMiddleware(middleware.NewTestGlobalMiddleware, fxhttpserver.GlobalUse),
			fxhttpserver.AsHandler("GET", "/bar", handler.NewTestBarHandler, middleware.NewTestHandlerMiddleware),
			fxhttpserver.AsHandler("GET,POST", "/baz", handler.NewTestBazHandler, middleware.NewTestHandlerMiddleware),
			fxhttpserver.AsHandlersGroup(
				"/foo",
				[]*fxhttpserver.HandlerRegistration{
					fxhttpserver.NewHandlerRegistration("GET", "/bar", handler.NewTestBarHandler, middleware.NewTestHandlerMiddleware),
					fxhttpserver.NewHandlerRegistration("GET,POST", "/baz", handler.NewTestBazHandler, middleware.NewTestHandlerMiddleware),
				},
				middleware.NewTestGroupMiddleware,
			),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter),
	).RequireStart().RequireStop()

	// [GET] /bar
	req := httptest.NewRequest(http.MethodGet, "/bar", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "bar: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in bar handler",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/bar",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"bar span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /bar",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/bar"),
		semconv.HTTPStatusCode(http.StatusOK),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)

	// [GET] /baz
	req = httptest.NewRequest(http.MethodGet, "/baz", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "baz: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in baz handler",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/baz",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"baz span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /baz",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/baz"),
		semconv.HTTPStatusCode(http.StatusOK),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)

	// [POST] /baz
	req = httptest.NewRequest(http.MethodPost, "/baz", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "baz: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in baz handler",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "POST",
		"uri":       "/baz",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"baz span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"POST /baz",
		semconv.HTTPMethod(http.MethodPost),
		semconv.HTTPRoute("/baz"),
		semconv.HTTPStatusCode(http.StatusOK),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)

	// [GET] /foo/bar
	req = httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "bar: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "true", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GROUP middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in bar handler",
	})
	logtest.AssertHasNotLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/foo/bar",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"bar span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	assert.False(
		t,
		traceExporter.HasSpan(
			"GET /foo/bar",
			semconv.HTTPMethod(http.MethodGet),
			semconv.HTTPRoute("/foo/bar"),
			semconv.HTTPStatusCode(http.StatusOK),
			attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
		),
	)

	// [GET] /foo/baz
	req = httptest.NewRequest(http.MethodGet, "/foo/baz", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "baz: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "true", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GROUP middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in baz handler",
	})
	logtest.AssertHasNotLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/foo/baz",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"baz span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	assert.False(
		t,
		traceExporter.HasSpan(
			"GET /foo/baz",
			semconv.HTTPMethod(http.MethodGet),
			semconv.HTTPRoute("/foo/baz"),
			semconv.HTTPStatusCode(http.StatusOK),
			attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
		),
	)

	// [POST] /foo/baz
	req = httptest.NewRequest(http.MethodPost, "/foo/baz", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	req.Header.Add("x-foo", "foo")
	req.Header.Add("x-bar", "bar")
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "baz: test")
	assert.Equal(t, "true", rec.Header().Get("global-middleware"))
	assert.Equal(t, "true", rec.Header().Get("group-middleware"))
	assert.Equal(t, "true", rec.Header().Get("handler-middleware"))

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GLOBAL middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "GROUP middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "HANDLER middleware for app: test",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "in baz handler",
	})
	logtest.AssertHasNotLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "POST",
		"uri":       "/foo/baz",
		"status":    200,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"foo":       "foo",
		"bar":       "bar",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"baz span",
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
	assert.False(
		t,
		traceExporter.HasSpan(
			"POST /foo/baz",
			semconv.HTTPMethod(http.MethodPost),
			semconv.HTTPRoute("/foo/baz"),
			semconv.HTTPStatusCode(http.StatusOK),
			attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
		),
	)

	// [GET] /invalid
	req = httptest.NewRequest(http.MethodGet, "/invalid", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "warn",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/invalid",
		"status":    404,
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"error":     "code=404, message=Not Found",
		"message":   "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /invalid",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPStatusCode(http.StatusNotFound),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
}

func TestModuleWithConcreteResources(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsMiddleware(concreteGlobalMiddleware, fxhttpserver.GlobalUse),
			fxhttpserver.AsHandler("*", "/concrete", concreteHandler, concreteHandlerMiddleware),
			fxhttpserver.AsHandlersGroup(
				"/group",
				[]*fxhttpserver.HandlerRegistration{
					fxhttpserver.NewHandlerRegistration("*", "/concrete", concreteHandler, concreteHandlerMiddleware),
				},
				concreteGroupMiddleware,
			),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter),
	).RequireStart().RequireStop()

	// [GET] /concrete
	req := httptest.NewRequest(http.MethodGet, "/concrete", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "concrete")

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "CONCRETE GLOBAL middleware",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "CONCRETE HANDLER middleware",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "in concrete handler",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/concrete",
		"status":    200,
		"message":   "request logger",
		"requestID": testRequestId,
		"traceID":   testTraceId,
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /concrete",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/concrete"),
		semconv.HTTPStatusCode(http.StatusOK),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)

	// [GET] /group/concrete
	req = httptest.NewRequest(http.MethodGet, "/group/concrete", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "concrete")

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "CONCRETE GLOBAL middleware",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "CONCRETE GROUP middleware",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "CONCRETE HANDLER middleware",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"requestID": testRequestId,
		"traceID":   testTraceId,
		"message":   "in concrete handler",
	})
	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "info",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/group/concrete",
		"status":    200,
		"message":   "request logger",
		"requestID": testRequestId,
		"traceID":   testTraceId,
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /group/concrete",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/group/concrete"),
		semconv.HTTPStatusCode(http.StatusOK),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)

	// [GET] /invalid
	req = httptest.NewRequest(http.MethodGet, "/invalid", nil)
	req.Header.Add("x-request-id", testRequestId)
	req.Header.Add("traceparent", testTraceParent)
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":     "warn",
		"service":   "test",
		"module":    "httpserver",
		"method":    "GET",
		"uri":       "/invalid",
		"error":     "code=404, message=Not Found",
		"status":    404,
		"message":   "request logger",
		"requestID": testRequestId,
		"traceID":   testTraceId,
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /invalid",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPStatusCode(http.StatusNotFound),
		attribute.String(httpserver.TraceSpanAttributeHttpRequestId, testRequestId),
	)
}

func TestModuleWithEchoResources(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")

	var httpServer *echo.Echo

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsMiddleware(
				echomiddleware.Rewrite(map[string]string{"/abstract": "/concrete"}),
				fxhttpserver.GlobalPre,
			),
			fxhttpserver.AsHandler("GET", "/concrete", concreteHandler, echomiddleware.CORS()),
			fxhttpserver.AsHandlersGroup(
				"/group",
				[]*fxhttpserver.HandlerRegistration{
					fxhttpserver.NewHandlerRegistration("GET", "/concrete", concreteHandler, echomiddleware.CORS()),
				},
				echomiddleware.Secure(),
			),
		),
		fx.Populate(&httpServer),
	).RequireStart().RequireStop()

	// [GET] /abstract
	req := httptest.NewRequest(http.MethodGet, "/abstract", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Contains(t, rec.Body.String(), "concrete")
	assert.Equal(t, "Origin", rec.Header().Get(echo.HeaderVary)) // CORS middleware

	// [GET] /concrete
	req = httptest.NewRequest(http.MethodGet, "/concrete", nil)
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Contains(t, rec.Body.String(), "concrete")
	assert.Equal(t, "Origin", rec.Header().Get(echo.HeaderVary)) // CORS middleware

	// [GET] /group/concrete
	req = httptest.NewRequest(http.MethodGet, "/group/concrete", nil)
	rec = httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Contains(t, rec.Body.String(), "concrete")
	assert.Equal(t, "Origin", rec.Header().Get(echo.HeaderVary))              // CORS middleware
	assert.Equal(t, "SAMEORIGIN", rec.Header().Get(echo.HeaderXFrameOptions)) // Secure middleware
}

func TestModuleWithPanicRecoveryAndDebug(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter
	var metricsRegistry *prometheus.Registry

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsHandler("GET", "/panic", panicHandler),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter, &metricsRegistry),
	).RequireStart().RequireStop()

	// [GET] /bar
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"message": "test panic"`)
	assert.Contains(t, rec.Body.String(), `"stack": "*errors.errorString test panic`)

	logtest.AssertContainLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "error",
		"service": "test",
		"module":  "httpserver",
		"message": "[PANIC RECOVER] test panic",
	})

	logtest.AssertContainLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "error",
		"error":   "test panic",
		"service": "test",
		"module":  "httpserver",
		"stack":   "*errors.errorString test panic",
		"message": "error handler",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /panic",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/panic"),
		semconv.HTTPStatusCode(http.StatusInternalServerError),
	)

	expectedMetric := `
		# HELP http_server_requests_total Number of processed HTTP requests
		# TYPE http_server_requests_total counter
		http_server_requests_total{method="GET",path="/panic",status="5xx"} 1
	`
	err := testutil.GatherAndCompare(
		metricsRegistry,
		strings.NewReader(expectedMetric),
		"http_server_requests_total",
	)
	assert.NoError(t, err)
}

func TestModuleWithMetrics(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter
	var metricsRegistry *prometheus.Registry

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsHandler("GET", "/bar", handler.NewTestBarHandler),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter, &metricsRegistry),
	).RequireStart().RequireStop()

	// [GET] /bar
	req := httptest.NewRequest(http.MethodGet, "/bar", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "bar: test")

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"message": "in bar handler",
	})

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"method":  "GET",
		"uri":     "/bar",
		"status":  200,
		"message": "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /bar",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/bar"),
		semconv.HTTPStatusCode(http.StatusOK),
	)

	expectedMetric := `
		# HELP http_server_requests_total Number of processed HTTP requests
		# TYPE http_server_requests_total counter
		http_server_requests_total{method="GET",path="/bar",status="2xx"} 1
	`
	err := testutil.GatherAndCompare(
		metricsRegistry,
		strings.NewReader(expectedMetric),
		"http_server_requests_total",
	)
	assert.NoError(t, err)
}

func TestModuleWithMetricsWithNamespaceAndSubsystem(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("METRICS_NAMESPACE", "foo")
	t.Setenv("METRICS_SUBSYSTEM", "bar")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter
	var metricsRegistry *prometheus.Registry

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsHandler("GET", "/bar", handler.NewTestBarHandler),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter, &metricsRegistry),
	).RequireStart().RequireStop()

	// [GET] /bar
	req := httptest.NewRequest(http.MethodGet, "/bar", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "bar: test")

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"message": "in bar handler",
	})

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"method":  "GET",
		"uri":     "/bar",
		"status":  200,
		"message": "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /bar",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/bar"),
		semconv.HTTPStatusCode(http.StatusOK),
	)

	expectedMetric := `
		# HELP foo_bar_http_server_requests_total Number of processed HTTP requests
		# TYPE foo_bar_http_server_requests_total counter
		foo_bar_http_server_requests_total{method="GET",path="/bar",status="2xx"} 1
	`
	err := testutil.GatherAndCompare(
		metricsRegistry,
		strings.NewReader(expectedMetric),
		"foo_bar_http_server_requests_total",
	)
	assert.NoError(t, err)
}

func TestModuleWithTemplates(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")
	t.Setenv("TEMPLATES_ENABLED", "true")
	t.Setenv("TEMPLATES_PATH", "testdata/templates/*.html")

	var httpServer *echo.Echo
	var logBuffer logtest.TestLogBuffer
	var traceExporter tracetest.TestTraceExporter

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Provide(service.NewTestService),
		fx.Options(
			fxhttpserver.AsHandler("GET", "/template", handler.NewTestTemplateHandler),
		),
		fx.Populate(&httpServer, &logBuffer, &traceExporter),
	).RequireStart().RequireStop()

	// [GET] /template
	req := httptest.NewRequest(http.MethodGet, "/template", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "App name: test")

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"message": "in template handler",
	})

	logtest.AssertHasLogRecord(t, logBuffer, map[string]interface{}{
		"level":   "info",
		"service": "test",
		"module":  "httpserver",
		"method":  "GET",
		"uri":     "/template",
		"status":  200,
		"message": "request logger",
	})

	tracetest.AssertHasTraceSpan(
		t,
		traceExporter,
		"GET /template",
		semconv.HTTPMethod(http.MethodGet),
		semconv.HTTPRoute("/template"),
		semconv.HTTPStatusCode(http.StatusOK),
	)
}

func TestModuleWithCustomErrorHandler(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Options(
			fxhttpserver.AsHandler("GET", "/error", handler.NewTestErrorHandler),
			fxhttpserver.AsErrorHandler(errorhandler.NewTestErrorHandler),
		),
		fx.Populate(&httpServer),
	).RequireStart().RequireStop()

	// [GET] /error
	req := httptest.NewRequest(http.MethodGet, "/error", nil)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "error handled in test error handler of test: test error")
}

func TestModuleWithInvalidHandlerMethods(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo

	spyTB := spy.NewSpyTB()

	fxtest.New(
		spyTB,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Options(
			fxhttpserver.AsHandler("invalid", "/concrete", concreteHandler),
		),
		fx.Populate(&httpServer),
	).RequireStart().RequireStop()

	assert.NotZero(t, spyTB.Failures())
	assert.Contains(t, spyTB.Errors().String(), `failed to register http server resources: invalid HTTP method "INVALID"`)
}

func TestModuleWithInvalidHandlersGroupMethods(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")
	t.Setenv("APP_DEBUG", "true")

	var httpServer *echo.Echo

	spyTB := spy.NewSpyTB()

	fxtest.New(
		spyTB,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Options(
			fxhttpserver.AsHandlersGroup(
				"/group",
				[]*fxhttpserver.HandlerRegistration{
					fxhttpserver.NewHandlerRegistration("invalid", "/concrete", concreteHandler, concreteHandlerMiddleware),
				},
				concreteGroupMiddleware,
			),
		),
		fx.Populate(&httpServer),
	).RequireStart().RequireStop()

	assert.NotZero(t, spyTB.Failures())
	assert.Contains(t, spyTB.Errors().String(), `failed to register http server resources: invalid HTTP method "INVALID"`)
}

func TestModuleDecoration(t *testing.T) {
	t.Setenv("APP_CONFIG_PATH", "testdata/config")

	var httpServer *echo.Echo

	fxtest.New(
		t,
		fx.NopLogger,
		fxconfig.FxConfigModule,
		fxlog.FxLogModule,
		fxtrace.FxTraceModule,
		fxmetrics.FxMetricsModule,
		fxgenerate.FxGenerateModule,
		fxhttpserver.FxHttpServerModule,
		fx.Decorate(factory.NewTestHttpServerFactory),
		fx.Populate(&httpServer),
	).RequireStart().RequireStop()

	assert.False(t, httpServer.HideBanner)
}
