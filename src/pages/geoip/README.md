
Unlike other endpoints the Geo endpoint doesn't have a text based version, it simply contains too much information to be useful. If people think otherwise, please reach out and let me know.

This endpoint contains geographical information about an IP, such as its latitude and longitude, along with the owning (ASN) organisation.

## URIs

| Type   | URI                                                                          |
|--------|------------------------------------------------------------------------------|
| JSON   | `https://get.geojs.io/v1/ip/geo.json`  
         `https://get.geojs.io/v1/ip/geo/{ip address}.json`                         |
| JSONP  | `https://get.geojs.io/v1/ip/geo.js`  
         `https://get.geojs.io/v1/ip/geo/{ip address}.js`                           |

## Query Parameters

| Parameter  | Default | Description                       | Endpoint             |
|------------|---------|-----------------------------------|----------------------|
| `ip`       | None    | Allows searching of multiple IPs  | All                  |
| `callback` | `geoip` | JSONP callback                    | `/v1/ip/geo.js`      |

## Properties

| Property           | Type    | Description                                                                                   | Example                   |
|--------------------|---------|-----------------------------------------------------------------------------------------------|---------------------------|
| `ip`               | String  | Requested IP                                                                                  | `8.8.8.8`                 |
| `country`          | String  | Country name in English                                                                       | `Australia`               |
| `country_code`     | String  | Two letter [country code (ISO3166)](https://dev.maxmind.com/geoip/legacy/codes/iso3166/)      | `AU`                      |
| `country_code3`    | String  | Three letter country code                                                                     | `AUS`                     |
| `continent_code`   | String  | Three letter continent code                                                                    | `OC`                      |
| `city`             | String  | City name in English                                                                          | `Mountain View`           |
| `region`           | String  | Subdivision of the country the IP is within (State, region etc)                               | `California`              |
| `latitude`         | String  | IP latitude (Note: this is a string due to historic reasons)                                  | `37.4056`                 |
| `longitude`        | String  | IP longitude (Note: this is a string due to historic reasons)                                 | `-122.0775`               |
| `accuracy`         | Integer | Radius in kilometers around the specified location where the IP address is likely to be       | `5`                       |
| `timezone`         | String  | Time zone as specified by the [IANA Time Zone Database](http://www.iana.org/time-zones)       | `America/Los_Angeles`     |
| `organization_name`| String  | The organization that the IP is registered to (Note: `Unknown` when this field is unknown)    | `Google LLC`              |
| `asn`              | Integer | The autonomous system number associated with the IP address (Note: `64512` when unknown)     | `15169`                   |
| `organization`     | String  | The ASN and organization field combined (Note: this field is deprecated)                      | `AS15169 Google LLC`      |

## Examples

### JSON

```json
{
  "accuracy": 1000,
  "area_code": "0",
  "asn": 15169,
  "continent_code": "NA",
  "country": "United States",
  "country_code": "US",
  "country_code3": "USA",
  "ip": "8.8.8.8",
  "latitude": "37.751",
  "longitude": "-97.822",
  "organization": "AS15169 Google LLC",
  "organization_name": "Google LLC"
}
```
When multiple IPs are queried using the ip arg on a request you get a response like this:

```json
[
  {
    "accuracy": 1000,
    "area_code": "0",
    "asn": 15169,
    "continent_code": "NA",
    "country": "United States",
    "country_code": "US",
    "country_code3": "USA",
    "ip": "8.8.8.8",
    "latitude": "37.751",
    "longitude": "-97.822",
    "organization": "AS15169 Google LLC",
    "organization_name": "Google LLC"
  },
  {
    "accuracy": 1000,
    "area_code": "0",
    "asn": 14907,
    "continent_code": "NA",
    "country": "United States",
    "country_code": "US",
    "country_code3": "USA",
    "ip": "198.35.26.96",
    "latitude": "37.751",
    "longitude": "-97.822",
    "organization": "AS14907 Wikimedia Foundation Inc.",
    "organization_name": "Wikimedia Foundation Inc."
  }
]
```