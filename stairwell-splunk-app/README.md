#Stairwell App for Splunk
Add Stairwell enrichment data to your Splunk events with the Stairwell App for Splunk. This application uses Stairwell private malware analysis to integrate directly with your Splunk experience. Enrich Splunk events based on analyis of hostnames, IP Address and file hashes.

The Stairwell App for Splunk requires a valid Stairwell API license and Splunk user privileges required for app installation. When the app is installed you have access to Stairwell commands to provide data enrichment that extends your defences beyond the limitations of traditional SIEMS tools.

## Prerequisites
1. To use the Stairwell analysis capability you will require an Authentication Token and an Organization identifier.
1.1 If you have an existing Stairwell account, please go to https://app.stairwell.com/settings.  If not, please contact sales@stairwell.com
2. To install the Stairwell App for Splunk you require Splunk privileges that allow app installation and configuration. To use the Stairwell App for Splunk you require priv1, priv2???

## Installation
1. Download the app from <github>. This will be called stairwell-splunk-app.tar.gz
2. Log into your Splunk web interface.
3. Navigate to Apps > Manage Apps.
4. Click install app from file.
5. Use the file explorer to find the file you downloaded.
6. Click on upload. Once the upload is successful restart your Splunk web interface.
7. Stairwell for Splunk App will now appear under the list of apps installed.

## How to use
### Streaming command
This command operates on each event independently resulting from a search. It adds Stairwell enrichment data to each event that matches the type of data and the criteria given.
There are 3 types of data currently supported:
####Hostnames

Example: find any field in the event called "host" and add Stairwell hostname enrichment data to it.

```
| stairwell hostname="host"
```

####IP Addresses

Example: find any field in the event called "ipaddress" and add Stairwell IP Address enrichment data to it.

```
| stairwell ip="ipaddress"

####File hashes

Example: find any field in the event called "SHA256" and add Stairwell object enrichment data to it.

```
| stairwell object="SHA256"
```

File hashes currently supported include md5, SHA256, SHA512 <do we need to list these?>

## What Stairwell enrichment data is provided?
List the output schema for hostname, IP address and object.