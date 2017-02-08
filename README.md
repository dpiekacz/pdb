Public Peering Report Generator
==========================
<b>Description</b><br/>
The tool utilizes <a href="https://peeringdb.com/apidocs/" target="_blank">PeeringDB API</a> to collect and analize details about requested ASN.
The generated report includes:
- Total number of peering points.
- Total number of unique IXP operators/organizations.
- Total aggregated public peering capacity.
- Percentage of IPv4 and IPv6 enabled peering points.
- List of public peering points grouped by IXP name. Added and Updated columns will be highlighted when have changed in the last 60 days.
- Per IXP percentage of NSP/ISP, CDN, Enterprise and other participants (grouped by ASN).
- Per IXP total connected NSP/ISP, CDN, Enterprise and other participants capacity.
- World map with location and number of peering points.
- World map with total capacity of peering points.

<b>Roadmap</b><br/>
- Per IXP percentage, network type, total capacity and list of ASNs that do not peer at other IXPs.

<b>Usage</b><br/>
https://pdb.gixtools.net/asn/<b>_ASN_</b>/<br/>
where <b>_ASN_</b> is the Autonomic System Numer we must provide, for instance 15169 (Google)<br/>
Valid <b>_ASN_</b> ranges are 1-23455, 23457-64495 and 131072-397212.

<b>Examples</b><br/>
- <a href="https://pdb.gixtools.net/asn/2906/" target="_blank">Report about Netflix</a>
- <a href="https://pdb.gixtools.net/asn/15169/" target="_blank">Report about Google</a>
- <a href="https://pdb.gixtools.net/asn/714/" target="_blank">Report about Apple</a>
- <a href="https://pdb.gixtools.net/asn/46489/" target="_blank">Report about Twitch</a>
- <a href="https://pdb.gixtools.net/asn/23286/" target="_blank">Report about Hulu</a>
- <a href="https://pdb.gixtools.net/asn/32934/" target="_blank">Report about Facebook</a>
- <a href="https://pdb.gixtools.net/asn/32590/" target="_blank">Report about Valve</a>
- <a href="https://pdb.gixtools.net/asn/16509/" target="_blank">Report about Amazon</a>
- <a href="https://pdb.gixtools.net/asn/8075/" target="_blank">Report about Microsoft</a>
- <a href="https://pdb.gixtools.net/asn/20940/" target="_blank">Report about Akamai</a>
- <a href="https://pdb.gixtools.net/asn/13335/" target="_blank">Report about CloudFlare</a>
- <a href="https://pdb.gixtools.net/asn/2914/" target="_blank">Report about NTT</a>
- <a href="https://pdb.gixtools.net/asn/3356/" target="_blank">Report about Level 3</a>
- <a href="https://pdb.gixtools.net/asn/286/" target="_blank">Report about KPN</a>
- <a href="https://pdb.gixtools.net/asn/6939/" target="_blank">Report about Hurricane Electric</a>

<b>Requirements</b><br/>
- No OS specific features are used, code is developed and tested on Ubuntu 16.04.1 LTS (xenial)
- Python 2.x, tested with 2.7.12
- Python libraries:
 - redis
 - peeringdb
 - flask
 - pygal
 - pygal_maps_world
- Redis DB, tested with 3.0.6
