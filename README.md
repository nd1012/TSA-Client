# TSA Client

The TSA Client contains two components:

1. .NET 6 executeable CLI tool
2. .NET Standard 2.0 library

Using [BouncyCastle-PCL](https://github.com/clairernovotny/BouncyCastle-PCL) it can create a TSQ and validate the TSR (RFC 3161) that comes from a third party SaaS TSA (like [freeTSA.org](https://freetsa.org)).

## Basic usage

### CLI tool

#### Create timestamp

```
tsac --file source.file --tsa https://freetsa.org/tsr --tsq source.tsq --tsr source.tsr --token source.tst
```

This will create a timestamp response (SHA512) for the file `source.file` and write some files:

- `source.tsq`: The timestamp request
- `source.tsr`: The timestamp response
- `source.tst`: The timestamp token

The response is validated already at this point.

The parameters `tsq`, `tsr` and `token` are optional - anyway, you may want to use `tsr` at last.

#### Validate timestamp / source data

Validate a TSR against the TSQ:

```
tsac --tsq source.tsq --tsr source.tsr
```

Validate a TSR against the source data:

```
tsac --file source.file --tsr source.tsr
```

Validate the timestamp token signer certificate:

```
tsac --tsr source.tsr --cert /path/to/signer.crt
```

Validate the source data and the timestamp token signer certificate:

```
tsac --file source.file --tsr source.tsr --cert /path/to/signer.crt
```

#### Display information

TSQ:

```
tasc --tsq source.tsq -tsqInfo
```

TSR:

```
tasc --tsr source.tsr -tsrInfo
```

Timestamp token:

```
tasc --token source.tst -tokenInfo
```

#### Advanced usage

For a full list of parameters and their descriptions (including more examples):

```
tsac -help
```

### Library

The library exports the static class `TSA`, which is a high level wrapper for the BouncyCastle-PCL API:

```cs
using wan24.TSAClient;

// Create a TSQ (using SHA512 and including the signer certificates)
byte[] tsq = TSA.CreateRequest("source.file");

// Request the TSR
byte[] tsr = TSA.SendRequest(tsq, "https://freetsa.org/tsr");

// Validate the TSR
TSA.ValidateResponse(tsq, tsr);

// Validate the source data
TSA.ValidateSourceTsr("source.file", tsr);

// Extract the timestamp token
byte[] token = TSA.ExtractToken(tsr);

// Validate the source data using the timestamp token
TSA.ValidateSourceToken("source.file", token);

// Validate the timestamp token using the X509 signer certificate
TSA.ValidateToken(token, "/path/to/signer.crt");

// Get object information
foreach(string info in TSA.RequestInfo(tsq))
    Console.WriteLine($"TSQ: {info}");
foreach(string info in TSA.ResponseInfo(tsr))
    Console.WriteLine($"TSR: {info}");
foreach(string info in TSA.TokenInfo(token))
    Console.WriteLine($"Timestamp token: {info}");
```

All methods of the `TSA` class are XML documented.

## Good to know

Existing target files will be overwritten!

Per default `SHA512` is used as hash algorithm. All possible hash algorithms (to be specified using the `--algo [algorithm]` parameter):

- `sha1`
- `sha256`
- `sha384`
- `sha512`

Of course the TSA needs to support the chosen hash algorithm, too!

The TSA URI will get the TSQ as `application/timestamp-query` POST http request and needs to respond the TSR. If the TSA needs authentication f.e., you can use your own `HttpWebRequest` instance with a pre-configuration (only `ContentType` and `ContentLength` will be set when calling `SendRequest`):

```cs
// Request the TSR with a custom request object
using System.Net;
HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://freetsa.org/tsr");
// Configure req here...
byte[] tsr = TSA.SendRequest(tsq, uri: null, req: req);
```

Find a [list of free TSA servers at GitHub](https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710).

## Changes

### CLI tool

#### Version 1 (2021-12-02)

- initial version

### Library

#### Version 1 (2021-12-02)

- initial version
