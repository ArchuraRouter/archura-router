
# Archura Router

Uses Spring boot, Java HTTP client and virtual threads.

# Installation

The following steps explain, build, compile to native, create docker image, and run load test.
Refer to https://www.graalvm.org/latest/docs/getting-started/macos/ to install GraalVM without sdkman.

```shell
# use Graalvm Java 19 version
sdk install java 22.3.r19-grl

# install native image command line tool
gu install native-image
```

# Building and Running
```shell
# build project
mvn clean install

# generate native image configuration 
java --enable-preview -agentlib:native-image-agent=config-output-dir=src/main/resources/META-INF/native-image -jar target/archura-router-0.0.1-SNAPSHOT.jar

# create native image 
./mvnw native:compile -Pnative

# build docker image
docker build -t archura-router:0.0.1 .

# run docker image
docker run --rm -it --memory="32MB" --cpus="0.5" -p 8080:8080 --name archura-router archura-router:0.0.1

# you can follow the CPU and Memory usage of the container
docker stats
```

# Filters

## DomainFilter

The first filter in the global pre-filter chain. 

Uses the 'Host' header to find the current domain. 
Finds the DomainConfiguration in the global configuration 'domains' map,
and sets the DomainConfiguration to the current request attributes with `archura.current.domain` key.

If the 'domains' map does not contain the domain, the filter will fetch the configuration for this domain
and put the configuration to the 'domains' map. Otherwise, the filter will return a 404 response.

## TenantFilter

The second filter in the global pre-filter chain.

Uses the `extractConfiguration` configuration in the `TenantFilterConfiguration` to extract the Tenant ID. 
Uses the header, path and query configurations to extract the Tenant ID in that order.

If no tenant id is found, the default Tenant ID from DomainConfiguration `defaultTenantId` value is used. 
If the `defaultTenantId` value is null, the filter will return a 404 response. 

If the Tenant ID is found, the filter gets the TenantConfiguration from the DomainConfiguration `tenants` map,
and sets it to the current request attributes with `archura.current.tenant` key.

If the `tenants` map does not contain the Tenant ID, the filter returns a 404 response.

Here is an example of the `TenantFilterConfiguration`:

```json
{
  "__class": "io.archura.router.config.GlobalConfiguration$TenantFilterConfiguration",
  "parameters": {},
  "extractConfiguration": {
    "headerConfiguration": [
      {
        "name": "X-Tenant-ID",
        "regex": "(?<tenantId>.*)",
        "captureGroups": [
          "tenantId"
        ]
      }
    ],
    "pathConfiguration": [
      {
        "regex": "\\/(?<tenantId>.*)\\/.*",
        "captureGroups": [
          "tenantId"
        ]
      }
    ],
    "queryConfiguration": [
      {
        "name": "tenant_id",
        "regex": "(?<tenantId>.*)",
        "captureGroups": [
          "tenantId"
        ]
      }
    ]
  }
}
```
This configuration searched the header with name `X-Tenant-ID`, 
if not found, it will search the path for the first capture group,
otherwise, it will search the query parameter with name `tenant_id`.


## BlacklistFilter

Checks the client IP against the black list IP configuration.

Uses the following headers to get the client IP, otherwise, uses the request's remote address.
```
"X-Forwarded-For",
"Proxy-Client-IP",
"WL-Proxy-Client-IP",
"HTTP_X_FORWARDED_FOR",
"HTTP_X_FORWARDED",
"HTTP_X_CLUSTER_CLIENT_IP",
"HTTP_CLIENT_IP",
"HTTP_FORWARDED_FOR",
"HTTP_FORWARDED",
"HTTP_VIA",
"REMOTE_ADDR"
```

If the client IP is in the global black list or in the domain black list, 
the filter will return a 403 response.

Here is an example of the `BlacklistFilterConfiguration`:

```json
{
  "__class": "io.archura.router.config.GlobalConfiguration$BlackListFilterConfiguration",
  "parameters": {},
  "ips": [
    "10.20.30.40",
    "50.60.70.80"
  ],
  "domainIps": {
    "localhost:8080": [
      "10.20.30.40"
    ]
  }
}
```


## HeaderFilter

Adds, removes, validates and checks the mandatory headers.

The following placeholders can be used in the value template:
* request.path
* request.method
* request.query
* request.header.[REQUEST_HEADER_NAME]
if available in the request attributes, also:
* request.domain.name  
* request.tenant.name
* request.route.name
* match.path
* match.path.[CAPTURE_GROUP_NAME]
* match.header.[REQUEST_HEADER_NAME]
* match.query.[QUERY_PARAMETER_NAME]
* extract.path
* extract.path.[CAPTURE_GROUP_NAME]
* extract.header.[REQUEST_HEADER_NAME]
* extract.query.[QUERY_PARAMETER_NAME]

Here is an example of the `HeaderFilterConfiguration`:

```json
{
  "__class": "io.archura.router.config.GlobalConfiguration$HeaderFilterConfiguration",
  "parameters": {},
  "add": [
    {
      "name": "Archura-Original-Method",
      "value": "${request.method}"
    },
    {
      "name": "Archura-Original-Path",
      "value": "${request.path}"
    },
    {
      "name": "Archura-Request-Domain",
      "value": "${request.domain.name}"
    },
    {
      "name": "Archura-Request-Tenant",
      "value": "${request.tenant.name}"
    },
    {
      "name": "Another-Request-Header",
      "value": "some-value"
    }
  ],
  "remove": [
    {
      "name": "Some-Request-Header"
    }
  ],
  "validate": [
    {
      "name": "Only-Numbers-Header",
      "regex": "^\\d+$"
    }
  ],
  "mandatory": [
    {
      "name": "Mandatory-Header"
    }
  ]
}
```


## RouteMatchingFilter

Expects `archura.current.domain` and `archura.current.tenant` attributes in the request.

Uses the `methodRoutes` map in the `RouteMatchingFilterConfiguration` to find the route for the current request.

First tries to find the matching route for the current request method, 
otherwise, tries to find the matching route for the `*` method.

The following placeholders can be used in the value template:
* request.path
* request.method
* request.query
* request.header.[REQUEST_HEADER_NAME]
* request.domain.name
* request.tenant.name
* request.route.name
* match.path
* match.path.[CAPTURE_GROUP_NAME]
* match.header.[REQUEST_HEADER_NAME]
* match.query.[QUERY_PARAMETER_NAME]
* extract.path
* extract.path.[CAPTURE_GROUP_NAME]
* extract.header.[REQUEST_HEADER_NAME]
* extract.query.[QUERY_PARAMETER_NAME]

Here is an example of the `RouteMatchingFilterConfiguration`:
```json
{
  "__class": "io.archura.router.config.GlobalConfiguration$RouteMatchingFilterConfiguration",
  "parameters": {},
  "methodRoutes": {
    "GET": [
      {
        "name": "domain-route-01",
        "preFilters": {},
        "postFilters": {},
        "matchConfiguration": {
          "pathConfiguration": [
            {
              "regex": "/not-found.html",
              "captureGroups": []
            }
          ]
        },
        "extractConfiguration": {},
        "mapConfiguration": {
          "url": "http://localhost:9020/not-found.html",
          "headers": {
            "request-original-method": "${request.header.Archura-Original-Method}",
            "request-original-path": "${request.header.Archura-Original-Path}",
            "request-domain": "${request.header.Archura-Request-Domain}",
            "request-tenant": "${request.header.Archura-Request-Tenant}"
          }
        }
      }
    ],
    "*": [
      {
        "name": "default-route",
        "preFilters": {},
        "postFilters": {},
        "matchConfiguration": {
          "pathConfiguration": [
            {
              "regex": "/welcome.html",
              "captureGroups": []
            }
          ]
        },
        "extractConfiguration": {},
        "mapConfiguration": {
          "url": "http://localhost:9020/welcome.html",
          "headers": {}
        }
      }
    ]
  }
}
```




