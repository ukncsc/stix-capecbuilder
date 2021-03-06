Copyright (c) 2016 Crown Copyright (NCSC)

Permission is hereby granted, free of charge, to use, copy, modify, merge, distribute and/or sub-licence the software together with any associated documentation provided that it is solely for your own internal use and subject to the following conditions:

(1) The above copyright notice and this permission notice shall be included in all copies or substantial portions of the software.

(2) THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN ANY ACTION FOR CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# CAPEC-Builder

[![Code Health](https://landscape.io/github/ncscuk/capec-builder/master/landscape.svg?style=flat)](https://landscape.io/github/ncsc/capec-builder/master)

CAPEC Builder script that generates STIX TTP objects.

This script will looks at the first argument given to the script as a CAPCE ID and look it up from the CAPCE XML file (`capec_2-8.xml`). The output will be a TTP object based from that CAPEC ID including the following information:

- Referenced CAPEC ID
- Description
- Title
- Related TTPs
- Information Source

## Status

The script is still under active development and as such shouldn't be considered a finished product.

## Setup

To install the script you can clone the repository using `git clone`.

Before using the script you will need setup the config file with your own settings:

Before using this script you will need to setup the configuration file with your own settings:

1. Make a copy of the `config.json.template` file and rename it to `config.json`.
2. Enter your own settings inside your `config.json` file.

  - The `stix` key defines your namespace and prefix.
  - The `capec-file` key defines the location and name of the CAPEC XML content file.

Once setup your file should look like this:

```json
{
  "capec-file": "capec_2-8.xml",
  "ingest": [
    {
      "active": false,
      "endpoint": "http://kb.avengers.com/adapter/certuk_mod/import/",
      "user": "bot"
    }
  ],
  "stix": [
    {
      "ns": "http://avengers.com",
      "ns_prefix": "avengers"
    }
  ],
  "taxii": [
    {
      "active": false,
      "binding": "urn:stix.mitre.org:xml:1.1.1",
      "discovery_path": "/taxii-discovery-service",
      "host": "kb.avengers.com",
      "inbox_path": "/taxii-data",
      "password": "password",
      "ssl": false,
      "username": "username"
    }
  ]
}
```

## Usage

From a terminal/command prompt your can specify the CAPEC ID as the argument to build a TTP based on that CAPEC.

```
$ python capecbuilder.py 202
```

## Example Output

An example output can be found in the [Example](Example-Package-c4b7c3c3-4c78-4eda-8715-1f00aa48d918.xml) file. This examples uses CAPEC 202.
