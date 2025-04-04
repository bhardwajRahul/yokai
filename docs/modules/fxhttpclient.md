---
title: Modules - HTTP Client
icon: material/cube-outline
---

# :material-cube-outline: HTTP Client Module

[![ci](https://github.com/ankorstore/yokai/actions/workflows/fxhttpclient-ci.yml/badge.svg)](https://github.com/ankorstore/yokai/actions/workflows/fxhttpclient-ci.yml)
[![go report](https://goreportcard.com/badge/github.com/ankorstore/yokai/fxhttpclient)](https://goreportcard.com/report/github.com/ankorstore/yokai/fxhttpclient)
[![codecov](https://codecov.io/gh/ankorstore/yokai/graph/badge.svg?token=ghUBlFsjhR&flag=fxhttpclient)](https://app.codecov.io/gh/ankorstore/yokai/tree/main/fxhttpclient)
[![Deps](https://img.shields.io/badge/osi-deps-blue)](https://deps.dev/go/github.com%2Fankorstore%2Fyokai%2Ffxhttpclient)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/ankorstore/yokai/fxhttpclient)](https://pkg.go.dev/github.com/ankorstore/yokai/fxhttpclient)

## Overview

Yokai provides a [fxhttpclient](https://github.com/ankorstore/yokai/tree/main/fxhttpclient) module, offering a ready to use [Client](https://pkg.go.dev/net/http#Client) to your application.

It wraps the [httpclient](https://github.com/ankorstore/yokai/tree/main/httpclient) module, based on [net/http](https://pkg.go.dev/net/http).

## Installation

First install the module:

```shell
go get github.com/ankorstore/yokai/fxhttpclient
```

Then activate it in your application bootstrapper:

```go title="internal/bootstrap.go"
package internal

import (
	"github.com/ankorstore/yokai/fxcore"
	"github.com/ankorstore/yokai/fxhttpclient"
)

var Bootstrapper = fxcore.NewBootstrapper().WithOptions(
	// modules registration
	fxhttpclient.FxHttpClientModule,
	// ...
)
```

## Configuration

```yaml title="configs/config.yaml"
modules:
  http:
    client:
      timeout: 30                            # in seconds, 30 by default
      transport:
        max_idle_connections: 100            # 100 by default
        max_connections_per_host: 100        # 100 by default
        max_idle_connections_per_host: 100   # 100 by default
      log:
        request:
          enabled: true                      # to log request details, disabled by default
          body: true                         # to add request body to request details, disabled by default
          level: info                        # log level for request logging
        response:
          enabled: true                      # to log response details, disabled by default
          body: true                         # to add response body to request details, disabled by default
          level: info                        # log level for response logging
          level_from_response: true          # to use response code for response logging
      trace:
        enabled: true                        # to trace http calls, disabled by default
      metrics:
        collect:
          enabled: true                      # to collect http client metrics
          namespace: foo                     # http client metrics namespace (empty by default)
          subsystem: bar                     # http client metrics subsystem (empty by default)
        buckets: 0.1, 1, 10                  # to override default request duration buckets
        normalize:
          request_path: true                 # to normalize http request path, disabled by default
          request_path_masks:                # request path normalization masks (key: mask to apply, value: regex to match), empty by default
            /foo/{id}/bar?page={page}: /foo/(.+)/bar\?page=(.+)
          response_status: true              # to normalize http response status code (2xx, 3xx, ...), disabled by default
```

## Usage

This module makes available the [Client](https://pkg.go.dev/net/http#Client) in
Yokai dependency injection system.

To access it, you just need to inject it where needed, for example:

```go title="internal/service/example.go"
package service

import (
	"context"
	"net/http"
)

type ExampleService struct {
	client *http.Client
}

func ExampleService(client *http.Client) *ExampleService {
	return &ExampleService{
		client: client,
	}
}

func (s *ExampleService) Call(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req.WithContext(ctx))
}
```

## Logging

This module enables to log automatically the HTTP requests made by the [Client](https://pkg.go.dev/net/http#Client) and their responses:

```yaml title="configs/config.yaml"
modules:
  http:
    client:
      log:
        request:
          enabled: true              # to log request details, disabled by default
          body: true                 # to add request body to request details, disabled by default
          level: info                # log level for request logging
        response:
          enabled: true              # to log response details, disabled by default
          body: true                 # to add response body to request details, disabled by default
          level: info                # log level for response logging
          level_from_response: true  # to use response code for response logging
```

If `modules.http.client.log.response.level_from_response=true`, the response code will be used to determinate the log level:

- `code < 400`: log level configured in `modules.http.client.log.response.level`
- `400 <= code < 500`: log level `warn`
- `code >= 500`: log level `error`

The HTTP client logging will be based on the [log](fxlog.md) module configuration.

## Tracing

This module enables to trace automatically HTTP the requests made by the [Client](https://pkg.go.dev/net/http#Client):

```yaml title="configs/config.yaml"
modules:
  http:
    client:
      trace:
      	enabled: true # to trace http calls, disabled by default
```

The HTTP client tracing will be based on the [trace](fxtrace.md) module configuration.

## Metrics

This module enables to automatically generate metrics about HTTP the requests made by the [Client](https://pkg.go.dev/net/http#Client):

```yaml title="configs/config.yaml"
modules:
  http:
    client:
      metrics:
        collect:
          enabled: true                      # to collect http client metrics
          namespace: foo                     # http client metrics namespace (empty by default)
          subsystem: bar                     # http client metrics subsystem (empty by default)
        buckets: 0.1, 1, 10                  # to override default request duration buckets
        normalize:
          request_path: true                 # to normalize http request path, disabled by default
          request_path_masks:                # request path normalization masks (key: mask to apply, value: regex to match), empty by default
            /foo/{id}/bar?page={page}: /foo/(.+)/bar\?page=(.+)
          response_status: true              # to normalize http response status code (2xx, 3xx, ...), disabled by default
```

If `modules.http.client.metrics.normalize.request_path=true`, the `modules.http.client.metrics.normalize.request_path_masks` map will be used to try to apply masks on the metrics path label for better cardinality.


In this example, after calling `client.Get("https://example.com/foo/1/bar?page=2")`, the [core](fxcore.md) HTTP server will expose in the configured metrics endpoint:

```makefile title="[GET] /metrics"
# ...
# HELP http_client_request_duration_seconds Time spent performing HTTP requests
# TYPE http_client_request_duration_seconds histogram
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.005"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.01"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.025"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.05"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.1"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.25"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="0.5"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="1"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="2.5"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="5"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="10"} 1
http_client_request_duration_seconds_bucket{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}",le="+Inf"} 1
http_client_request_duration_seconds_sum{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}"} 0.00064455
http_client_request_duration_seconds_count{method="GET",host="https://example.com",path="/foo/{id}/bar?page={page}"} 1
# HELP http_client_requests_total Number of performed HTTP requests
# TYPE http_client_requests_total counter
http_client_requests_total{method="GET",status="2xx",host="https://example.com",path="/foo/{id}/bar?page={page}"} 1
```

## Testing

This module provides a [httpclienttest.NewTestHTTPServer()](https://github.com/ankorstore/yokai/blob/main/httpclient/httpclienttest/server.go) helper for testing your clients against a test server, that allows you:

- to define test HTTP roundtrips: a couple of test aware functions to define the request and the response behavior
- to configure several test HTTP roundtrips if you need to test successive calls

To use it:

```go  title="internal/service/example_test.go"
package service_test

import (
	"net/http"
	"testing"

	"github.com/ankorstore/yokai/httpclient"
	"github.com/ankorstore/yokai/httpclient/httpclienttest"
	"github.com/stretchr/testify/assert"
)

func TestHTTPClient(t *testing.T) {
	t.Parallel()

	// retrieve your client
	var client *http.Client

	// test server preparation
	testServer := httpclienttest.NewTestHTTPServer(
		t,
		// configures a roundtrip for the 1st client call (/foo)
		httpclienttest.WithTestHTTPRoundTrip(
			// func to configure / assert on the client request
			func(tb testing.TB, req *http.Request) error {
				tb.Helper()

				// performs some assertions
				assert.Equal(tb, "/foo", req.URL.Path)

				// returning an error here will make the test fail, if needed
				return nil
			},
			// func to configure / assert on the response for the client
			func(tb testing.TB, w http.ResponseWriter) error {
				tb.Helper()

				// prepares the response for the client
				w.Header.Set("foo", "bar")

				// performs some assertions
				assert.Equal(tb, "bar", w.Header.Get("foo"))

				// returning an error here will make the test fail, if needed
				return nil
			},
		),
		// configures a roundtrip for the 2nd client call (/bar)
		httpclienttest.WithTestHTTPRoundTrip(
			// func to configure / assert on the client request
			func(tb testing.TB, req *http.Request) error {
				tb.Helper()

				assert.Equal(tb, "/bar", req.URL.Path)
				
				return nil
			},
			// func to configure / assert on the response for the client
			func(tb testing.TB, w http.ResponseWriter) error {
				tb.Helper()

				w.WriteHeader(http.StatusInternalServerError)
				
				return nil
			},
		),
	)

	// 1st client call (/foo)
	resp, err := client.Get(testServer.URL + "/foo")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "bar", resp.Header.Get("foo"))

	// 2nd client call (/bar)
	resp, err = client.Get(testServer.URL + "/bar")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
```

You can find more complete examples in the module [tests](https://github.com/ankorstore/yokai/blob/main/httpclient/httpclienttest/server_test.go).
