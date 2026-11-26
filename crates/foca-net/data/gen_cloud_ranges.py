#!/usr/bin/env python3
"""Regenerates cloud_ranges.txt.gz from the providers' published lists.

Inputs (in the current directory):
  ips-v4, ips-v6          https://www.cloudflare.com/ips-v4 , /ips-v6
  ip-ranges.json          https://ip-ranges.amazonaws.com/ip-ranges.json
  azure.json              ServiceTags_Public_*.json (https://www.microsoft.com/download/details.aspx?id=56519)
  cloud.json              https://www.gstatic.com/ipranges/cloud.json
  public-ip-list          https://api.fastly.com/public-ip-list
  google.csv              https://digitalocean.com/geo/google.csv
  as<N>.json              https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<N>
                          (Akamai: 20940 16625 32787; Hetzner: 24940 213230)

Output: one `provider<TAB>kind<TAB>cidr` line per collapsed prefix, gzip-compressed.
"""
import csv
import gzip
import ipaddress
import json
from collections import defaultdict

out = defaultdict(set)


def add(provider, kind, cidr):
    try:
        out[(provider, kind)].add(ipaddress.ip_network(cidr.strip(), strict=False))
    except ValueError:
        pass


for f in ("ips-v4", "ips-v6"):
    for line in open(f):
        if line.strip():
            add("cloudflare", "cdn", line)

aws = json.load(open("ip-ranges.json"))
for p in aws["prefixes"]:
    add("aws", "cdn" if p["service"] == "CLOUDFRONT" else "cloud", p["ip_prefix"])
for p in aws["ipv6_prefixes"]:
    add("aws", "cdn" if p["service"] == "CLOUDFRONT" else "cloud", p["ipv6_prefix"])

az = json.load(open("azure.json"))
for v in az["values"]:
    if v["name"] == "AzureFrontDoor.Frontend":
        kind = "cdn"
    elif v["name"] == "AzureCloud":
        kind = "cloud"
    else:
        continue
    for c in v["properties"]["addressPrefixes"]:
        add("azure", kind, c)

for p in json.load(open("cloud.json"))["prefixes"]:
    add("gcp", "cloud", p.get("ipv4Prefix") or p.get("ipv6Prefix"))

fastly = json.load(open("public-ip-list"))
for c in fastly.get("addresses", []) + fastly.get("ipv6_addresses", []):
    add("fastly", "cdn", c)

for row in csv.reader(open("google.csv")):
    if row:
        add("digitalocean", "hosting", row[0])

for asn, provider, kind in (
    (20940, "akamai", "cdn"),
    (16625, "akamai", "cdn"),
    (32787, "akamai", "cdn"),
    (24940, "hetzner", "hosting"),
    (213230, "hetzner", "hosting"),
):
    for p in json.load(open(f"as{asn}.json"))["data"]["prefixes"]:
        add(provider, kind, p["prefix"])

lines = []
for (provider, kind), nets in sorted(out.items()):
    for v in (4, 6):
        for n in ipaddress.collapse_addresses(x for x in nets if x.version == v):
            lines.append(f"{provider}\t{kind}\t{n}")

with gzip.GzipFile("cloud_ranges.txt.gz", "wb", mtime=0, compresslevel=9) as g:
    g.write(("\n".join(lines) + "\n").encode())
print(len(lines), "prefixes")
