# Stairwell App for Splunk

Add Stairwell enrichment data to your Splunk events with the Stairwell App for Splunk. This application uses Stairwell private malware analysis to integrate directly with your Splunk experience. Enrich Splunk events based on analyis of hostnames, IP Address and file hashes.

The Stairwell App for Splunk requires a valid Stairwell API license and Splunk user privileges required for app installation. The app makes calls to the Stairwell API. When the app is installed you have access to Stairwell commands to provide data enrichment that extends your defences beyond the limitations of traditional SIEMS tools.

The Stairwell App for Splunk is compatible with Splunk Enterprise 9.4.0

For the very latest information on how to use this app visit [Stairwell App for Splunk](https://docs.stairwell.com/docs/configure-splunk-application)

## Details
### Streaming command
This command operates on each event independently resulting from a search. It adds Stairwell enrichment data to each event that matches the type of data and the criteria given.

There are 3 types of data currently supported:
#### Hostnames
Example: find any field in the event called "host" and add Stairwell hostname enrichment data to it.

```
| makeresults | eval host = "google.com" | stairwell hostname="host"
```

#### IP Addresses
Example: find any field in the event called "ipaddress" and add Stairwell IP Address enrichment data to it.

```
| makeresults | eval ip = "192.168.0.1" | stairwell ip="ip"
```

#### Objects (file hashes)
File hashes currently supported include MD5, SHA1, SHA256.
Example: find any field in the event called "SHA256" and add Stairwell object enrichment data to it.

```
| makeresults | eval hash = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da" | stairwell object="hash"
```

### What Stairwell enrichment data is provided?
See [Stairwell App for Splunk](https://docs.stairwell.com/docs/configure-splunk-application) for details.

## Installation
### Prerequisites
1. To use the Stairwell analysis capability you will require an Authentication Token and an Organization Id.
1.1 If you have an existing Stairwell account, please go to https://app.stairwell.com/settings.  If not, please contact sales@stairwell.com
2. To install the Stairwell App for Splunk you require Splunk privileges that allow app installation and configuration. To use the Stairwell App for Splunk you require priv1, priv2???

### Installing
1. Download the app from <github>. This will be called stairwell-splunk-app-1.0.0.tar.gz
2. Log into your Splunk web interface.
3. Navigate to Apps > Manage Apps.
4. Click install app from file.
5. Use the file explorer to find the file you downloaded.
6. Click on upload. 
7. Once the upload is successful you can configure the app.
8. However, it is recommended that you select "Set up later".
9. Perform a Splunk restart. ```$SPLUNK_HOME/bin/splunk restart```
10. Log into your Splunk web interface again.
11. Navigate to Apps > Stairwell App for Splunk
12. Click the box that says Continue to app setup page
13. Enter your Authentication Token and Organization Id then Submit
14. Stairwell for Splunk App home page will now appear.

## Troubleshooting
Please contact __support@stairwell.com__ for help.

## Contact
Please contact __support@stairwell.com__.

## Version History
|Version|Release Date|Compatibility|Compliance|Actions|
|-------|------------|-------------|----------|-------|
|1.0.0|TBD|Splunk Enterprise|N/A|Download link|